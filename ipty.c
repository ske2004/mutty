#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "umbox/umka_api/umka_api.h"

static void
ipty_fatal(const char *msg)
{
  fprintf(stderr, "%s", msg);
  exit(-1);
}

#ifdef _WIN32
#include <windows.h>

typedef struct
{
  HANDLE in_pty;
  HANDLE out_pty;
  HANDLE in_my;
  HANDLE out_my;
  HPCON pty;
  HANDLE hproc;
  HANDLE hthread;
  STARTUPINFOEXW siex;
  BYTE *attr_list;
} ipty_t;

/* https://devblogs.microsoft.com/commandline/windows-command-line-introducing-the-windows-pseudo-console-conpty/ */
HRESULT ipty_init_siex(ipty_t *ipty)
{
  HRESULT hr = E_UNEXPECTED;
  size_t size;

  ipty->siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
  InitializeProcThreadAttributeList(NULL, 1, 0, &size);
  ipty->attr_list = calloc(size, 1);
  ipty->siex.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)ipty->attr_list;
  bool is_success = InitializeProcThreadAttributeList(ipty->siex.lpAttributeList, 1, 0, (PSIZE_T)&size);

  if (is_success) {
    is_success = UpdateProcThreadAttribute(
      ipty->siex.lpAttributeList,
      0,
      PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
      ipty->pty,
      sizeof(HPCON),
      NULL,
      NULL
    );

    hr = is_success ? S_OK : HRESULT_FROM_WIN32(GetLastError());
  } else {
    hr = HRESULT_FROM_WIN32(GetLastError());
  }

  return hr;
}

ipty_t ipty_new(int16_t w, int16_t h)
{
  ipty_t ipty = { 0 };

  if (!CreatePipe(&ipty.in_pty, &ipty.in_my, NULL, 0)) {
    ipty_fatal("failed to open in pipe");
  }
  if (!CreatePipe(&ipty.out_my, &ipty.out_pty, NULL, 0)) {
    ipty_fatal("failed to open out pipe");
  }

  if (FAILED(CreatePseudoConsole((COORD){w, h}, ipty.in_pty, ipty.out_pty, 0, &ipty.pty))) {
    ipty_fatal("failed to create pty");
  }

  ipty_init_siex(&ipty);

  wchar_t cmdline[] = L"C:\\windows\\system32\\cmd.exe";
  PROCESS_INFORMATION pif;
  bool is_success = CreateProcessW(
    NULL,
    cmdline,
    NULL,
    NULL,
    FALSE,
    EXTENDED_STARTUPINFO_PRESENT,
    NULL,
    NULL,
    &ipty.siex.StartupInfo,
    &pif
  );

  ipty.hproc = pif.hProcess;
  ipty.hthread = pif.hThread;
  if (!is_success) {
    ipty_fatal("failed opening cmd");
  }

  return ipty;
}

void ipty_resize(ipty_t *ipty, int16_t w, int16_t h)
{
  ResizePseudoConsole(ipty->pty, (COORD){w, h});
}

int ipty_read(ipty_t *ipty, void *data, size_t size)
{
  DWORD number_of_bytes_read;
  DWORD number_of_bytes_avail;
  DWORD number_of_bytes_remaining;
  bool read_ok = PeekNamedPipe(
    ipty->out_my, data, size,
    &number_of_bytes_read,
    &number_of_bytes_avail,
    &number_of_bytes_remaining
  );
  if (read_ok && number_of_bytes_read>0) {
    read_ok = ReadFile(ipty->out_my, data, number_of_bytes_read, &number_of_bytes_read, NULL);
  }

  if (!read_ok) {
    return -1;
  }

  return number_of_bytes_read;
}

int ipty_write(ipty_t *ipty, void *data, size_t size)
{
  DWORD number_of_bytes_written;
  bool write_ok = WriteFile(ipty->in_my, data, size, &number_of_bytes_written, NULL);
  if (!write_ok) {
    return -1;
  }

  return number_of_bytes_written;
}

void ipty_del(ipty_t *ipty)
{
  /* hangs the program so im removing this for now */
  // TerminateThread(ipty->hthread, 0);
  // TerminateProcess(ipty->hproc, 0);
  // CloseHandle(ipty->in_pty);
  // CloseHandle(ipty->out_pty);
  // CloseHandle(ipty->in_my);
  // CloseHandle(ipty->out_my);
  // DeleteProcThreadAttributeList(ipty->siex.lpAttributeList);
  // ClosePseudoConsole(ipty->pty);
}

#else
#include <pty.h>
#include <poll.h>
#include <unistd.h>

typedef struct {
  int master_fd;
  int slave_fd;
} ipty_t;

ipty_t ipty_new(int16_t w, int16_t h)
{
  extern const char **environ;

  int master_fd;
  int slave_fd;

  if (w<0) w=0;
  if (h<0) h=0;

  struct winsize ws = {(uint16_t)h, (uint16_t)w, 0, 0};
  if (openpty(&master_fd, &slave_fd, NULL, NULL, &ws) < 0) {
    ipty_fatal("failed to open pty");
  }

  int p = fork();
  if (p == 0) {
    close(master_fd);

    setsid();
    if (ioctl(slave_fd, TIOCSCTTY, NULL) == -1) {
      ipty_fatal("failed to mark");
    }

    dup2(slave_fd, 0);
    dup2(slave_fd, 1);
    dup2(slave_fd, 2);
    close(slave_fd);

    const char *shell = getenv("SHELL") ? getenv("SHELL") : "/bin/sh";
    execle(shell, shell, NULL, environ);
  }

  return (ipty_t){master_fd, slave_fd};
}

void ipty_del(ipty_t *ipty)
{
  /* no idea lol */
}

void ipty_resize(ipty_t *ipty, int16_t w, int16_t h)
{
  if (w<0) w=0;
  if (h<0) h=0;

  struct winsize ws = {(uint16_t)h, (uint16_t)w, 0, 0};
  ioctl(ipty->master_fd, TIOCSWINSZ, &ws);
}

int ipty_read(ipty_t *ipty, void *b, size_t n)
{
  struct pollfd fds[1] = { 0 };
  fds[0].fd = ipty->master_fd;
  fds[0].events = POLLIN;

  if (poll(fds, 1, 0) != 1) {
    return -1;
  }

  return read(ipty->master_fd, b, n);
}

int ipty_write(ipty_t *ipty, void *b, size_t n)
{
  return write(ipty->master_fd, b, n);
}

#endif

void umkaIptyDel(UmkaStackSlot *p, UmkaStackSlot *r)
{
  void *umka = umkaGetInstance(r);
  UmkaAPI *api = umkaGetAPI(umka);
  
  ipty_del(api->umkaGetParam(p, 0)->ptrVal);
}

UMKA_EXPORT void umkaIptyNew(UmkaStackSlot *p, UmkaStackSlot *r)
{
  void *umka = umkaGetInstance(r);
  UmkaAPI *api = umkaGetAPI(umka);

  ipty_t **out = api->umkaGetParam(p, 0)->ptrVal;
  ipty_t *ipty = api->umkaAllocData(umka, sizeof(ipty_t), umkaIptyDel);
  *ipty = ipty_new(api->umkaGetParam(p, 1)->intVal, api->umkaGetParam(p, 2)->intVal);
  *out = ipty;
}

UMKA_EXPORT void umkaIptyResize(UmkaStackSlot *p, UmkaStackSlot *r)
{
  void *umka = umkaGetInstance(r);
  UmkaAPI *api = umkaGetAPI(umka);

  ipty_t *ipty = api->umkaGetParam(p, 0)->ptrVal;
  ipty_resize(ipty, api->umkaGetParam(p, 1)->intVal, api->umkaGetParam(p, 2)->intVal);
}

UMKA_EXPORT void umkaIptyRead(UmkaStackSlot *p, UmkaStackSlot *r)
{
  void *umka = umkaGetInstance(r);
  UmkaAPI *api = umkaGetAPI(umka);

  ipty_t *ipty = api->umkaGetParam(p, 0)->ptrVal;
  UmkaDynArray(uint8_t) *d = api->umkaGetParam(p, 1)->ptrVal;
  api->umkaGetResult(p, r)->intVal = ipty_read(ipty, d->data, api->umkaGetDynArrayLen(d));
}

UMKA_EXPORT void umkaIptyWrite(UmkaStackSlot *p, UmkaStackSlot *r)
{
  void *umka = umkaGetInstance(r);
  UmkaAPI *api = umkaGetAPI(umka);
 
  ipty_t *ipty = api->umkaGetParam(p, 0)->ptrVal;
  UmkaDynArray(uint8_t) *d = api->umkaGetParam(p, 1)->ptrVal;
  api->umkaGetResult(p, r)->intVal = ipty_write(ipty, d->data, api->umkaGetDynArrayLen(d));
}
