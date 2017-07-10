#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/unistd.h>
#include <spin/spindrv.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#define RING_SIZE 12*1024*1024
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


static int initialized = 0;

static int m_ringSize;
static int spindrv_devfd;
static void* m_pDBuffer;
typedef int (*orig_pread_f_type)(int fd, void *buf, size_t count, off_t offset);
orig_pread_f_type orig_pread;
static void _ini() __attribute__((constructor(1000)));
static void _fini() __attribute__((destructor));

static void _ini(void)
{
	if (initialized)
		return;
	orig_pread = (orig_pread_f_type) dlsym(RTLD_NEXT, "pread64");
	initialized = 1;
	spindrv_devfd = open("/dev/spindrv", O_RDWR);
	if (spindrv_devfd < 0)
		return;

	m_ringSize = DIV_ROUND_UP(RING_SIZE, 4096) + 1;

	//Allocate the Dummy Buffer
	if (posix_memalign(&m_pDBuffer, 4096, RING_SIZE) != 0) {
		goto errCleanup;
	}
	memset(m_pDBuffer, 0, RING_SIZE);
	//Prepare IOCTL call to driver
	spindrv_ioctl_inc_t ioctl_args;
	spindrv_ioctl_param_union send_ioctl;
	memset(&ioctl_args, 0, sizeof(spindrv_ioctl_inc_t));

	//Populate with size and dummy buffer pointer
	ioctl_args.size = RING_SIZE;
	ioctl_args.addr = m_pDBuffer;



	//check if device open succeeded
	if (spindrv_devfd < 0) {
		goto errCleanup;
	}

	send_ioctl.set = ioctl_args;

	//Check if IOCTL call failed
	if (ioctl(spindrv_devfd, SPIN_IOCTL_NEW_BUFFER, &send_ioctl) != 0) {
		goto errCleanup;
	}

	return;
errCleanup:

	if (m_pDBuffer != NULL) {
		free(m_pDBuffer);
	}

	m_pDBuffer = NULL;

	if (fcntl(spindrv_devfd, F_GETFD) != -1 || errno != EBADF) {
		close(spindrv_devfd);
	}
	printf("something was wrong...\n");
}

void myinit(void)
{
	_ini();
}

static void _fini()
{
	if (initialized) {
		//send IOCTL to remove entry
		spindrv_ioctl_inc_t ioctl_args;
		spindrv_ioctl_param_union send_ioctl;
		memset(&ioctl_args, 0, sizeof(spindrv_ioctl_inc_t));
		send_ioctl.set = ioctl_args;

		ioctl(spindrv_devfd, SPIN_IOCTL_REMOVE, &send_ioctl);

		//Free m_pDBuffer memory
		free(m_pDBuffer);

		close(spindrv_devfd);
	}

}

ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
{
	int ioctl_ret;
	spindrv_ioctl_pread_t ioctl_args;
	spindrv_ioctl_param_union send_ioctl;
	memset(&ioctl_args, 0, sizeof(spindrv_ioctl_pread_t));

	ioctl_args.fd = fd;
	ioctl_args.buf = buf;
	ioctl_args.count = count;
	ioctl_args.offset = offset;
	ioctl_args.m_pDBuffer = m_pDBuffer;
	ioctl_args.read_return = 0;
	send_ioctl.readArgs = ioctl_args;
	if (spindrv_devfd < 0 || !initialized) {
		return orig_pread(fd, buf, count, offset);

	}
	ioctl_ret = ioctl(spindrv_devfd, SPIN_IOCTL_READ, &send_ioctl);

	switch (ioctl_ret) {

	case 1:
	{
		return send_ioctl.readArgs.read_return;
		break;

	}

	case 2:
	{
		return send_ioctl.readArgs.read_return;
		break;
	}
	default:
	{
		printf("something went wrong in read override%d \n", ioctl_ret);
		return -1;
	}

	}

}
