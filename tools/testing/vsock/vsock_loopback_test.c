// SPDX-License-Identifier: GPL-2.0-only
/*
 * vsock_loopback_test - vsock_loopback.ko test suite
 *
 * Copyright (C) 2022 Bytedance
 *
 * Author: Bobby Eshleman <bobby.eshleman@bytedance.com>
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <poll.h>

#include "timeout.h"
#include "util.h"

#define PORT 1234

/* Connect to port and return the file descriptor. */
static int vsock_connect_loopback(unsigned int port, int type)
{
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = port,
			.svm_cid = VMADDR_CID_LOCAL,
		},
	};
	int ret;
	int fd;

	fd = socket(AF_VSOCK, type, 0);

	timeout_begin(TIMEOUT);
	do {
		ret = connect(fd, &addr.sa, sizeof(addr.svm));
		timeout_check("connect");
	} while (ret < 0 && errno == EINTR);
	timeout_end();

	if (ret < 0) {
		int old_errno = errno;

		close(fd);
		fd = -1;
		errno = old_errno;
	}
	return fd;
}

static int vsock_stream_connect_loopback(unsigned int port)
{
	return vsock_connect_loopback(port, SOCK_STREAM);
}

static int vsock_seqpacket_connect_loopback(unsigned int port)
{
	return vsock_connect_loopback(port, SOCK_SEQPACKET);
}

static int vsock_dgram_connect_loopback(unsigned int port)
{
	return vsock_connect_loopback(port, SOCK_DGRAM);
}

/* Listen on <port> and return the first incoming connection.  The remote
 * address is stored to clientaddrp.  clientaddrp may be NULL.
 */
static int vsock_accept_loopback(unsigned int port, struct sockaddr_vm *clientaddrp,
				 int type)
{
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = port,
			.svm_cid = VMADDR_CID_LOCAL,
		},
	};
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} clientaddr;
	socklen_t clientaddr_len = sizeof(clientaddr.svm);
	int fd;
	int client_fd;
	int old_errno;

	fd = socket(AF_VSOCK, type, 0);

	if (bind(fd, &addr.sa, sizeof(addr.svm)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (listen(fd, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	timeout_begin(TIMEOUT);
	do {
		client_fd = accept(fd, &clientaddr.sa, &clientaddr_len);
		timeout_check("accept");
	} while (client_fd < 0 && errno == EINTR);
	timeout_end();

	old_errno = errno;
	close(fd);
	errno = old_errno;

	if (client_fd < 0)
		return client_fd;

	if (clientaddr_len != sizeof(clientaddr.svm)) {
		fprintf(stderr, "unexpected addrlen from accept(2), %zu\n",
			(size_t)clientaddr_len);
		exit(EXIT_FAILURE);
	}
	if (clientaddr.sa.sa_family != AF_VSOCK) {
		fprintf(stderr, "expected AF_VSOCK from accept(2), got %d\n",
			clientaddr.sa.sa_family);
		exit(EXIT_FAILURE);
	}

	if (clientaddrp)
		*clientaddrp = clientaddr.svm;
	return client_fd;
}

int vsock_stream_accept_loopback(unsigned int port,
				 struct sockaddr_vm *clientaddrp)
{
	return vsock_accept_loopback(port, clientaddrp, SOCK_STREAM);
}

int vsock_seqpacket_accept_loopback(unsigned int port,
				    struct sockaddr_vm *clientaddrp)
{
	return vsock_accept_loopback(port, clientaddrp, SOCK_SEQPACKET);
}

static void test_dgram_loopback(const struct test_opts *opts)
{
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = PORT,
			.svm_cid = VMADDR_CID_LOCAL,
		},
	};
	int len = sizeof(addr.sa);
	int sendfd, recvfd;
	int ret;

	recvfd = socket(AF_VSOCK, SOCK_DGRAM, 0);
	if (recvfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	ret = bind(recvfd, &addr.sa, sizeof(addr.svm));
	if (ret < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	sendfd = vsock_dgram_connect_loopback(addr.svm.svm_port);
	send_byte(sendfd, 1, 0);
	recvfrom_byte(recvfd, &addr.sa, &len, 1, 0);

	close(sendfd);
	close(recvfd);
}

static int stream_loopback_send_byte(void)
{
	int fd;

	fd = vsock_stream_connect_loopback(PORT);
	if (fd < 0) {
		perror("connect");
		return EXIT_FAILURE;
	}
	send_byte(fd, 1, 0);
	close(fd);
	return EXIT_SUCCESS;
}

/* Fork a child process and call the function 'fn' from child context.
 *
 * Return the child pid if current thread is the parent. Otherwise, the child
 * thread exits with exit_code == the return value of the function 'fn'..
 */
static int fork_and_call(int (*fn)(void))
{
	pid_t pid;

	pid = fork();
	if (pid != 0)
		return pid;

	exit(fn());
}

static void test_stream_loopback(const struct test_opts *opts)
{
	int childpid;
	int wstatus;
	int fd;

	childpid = fork_and_call(stream_loopback_send_byte);

	fd = vsock_stream_accept_loopback(PORT, NULL);
	if (fd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	recv_byte(fd, 0, 0);
	close(fd);

	waitpid(childpid, &wstatus, 0);
}

static int seqpacket_loopback_send_byte(void)
{
	int fd;

	fd = vsock_seqpacket_connect_loopback(PORT);
	if (fd < 0) {
		perror("connect");
		return EXIT_FAILURE;
	}
	send_byte(fd, 1, 0);
	close(fd);
	return EXIT_SUCCESS;
}


static void test_seqpacket_loopback(const struct test_opts *opts)
{
	int childpid;
	int wstatus;
	int fd;

	childpid = fork_and_call(seqpacket_loopback_send_byte);

	fd = vsock_seqpacket_accept_loopback(PORT, NULL);
	if (fd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	recv_byte(fd, 0, 0);
	close(fd);

	waitpid(childpid, &wstatus, 0);
}

static struct test_case test_cases[] = {
	{
		.name = "SOCK_STREAM loopback",
		.run_client = test_stream_loopback,
	},
	{
		.name = "SOCK_SEQPACKET loopback",
		.run_client = test_seqpacket_loopback,
	},
	{
		.name = "SOCK_DGRAM loopback",
		.run_client = test_dgram_loopback,
	},
	{},
};

static const char optstring[] = "";
static const struct option longopts[] = {
	{
		.name = "list",
		.has_arg = no_argument,
		.val = 'l',
	},
	{
		.name = "skip",
		.has_arg = required_argument,
		.val = 's',
	},
	{
		.name = "help",
		.has_arg = no_argument,
		.val = '?',
	},
	{},
};

static void usage(void)
{
	fprintf(stderr, "Usage: vsock_loopback_test [--help] [--list] [--skip=<test_id>]\n"
		"\n"
		"\n"
		"Run vsock_loopback.ko tests. vsock_loopback must be enabled.\n"
		"\n"
		"Options:\n"
		"  --help                 This help message\n"
		"  --list                 List of tests that will be executed\n"
		"  --skip <test_id>       Test ID to skip;\n"
		"                         use multiple --skip options to skip more tests\n"
		);
	exit(EXIT_FAILURE);
}

static void run_loopback_tests(const struct test_case *test_cases)
{
	int i;

	for (i = 0; test_cases[i].name; i++) {
		printf("%d - %s...", i, test_cases[i].name);
		fflush(stdout);

		if (test_cases[i].skip) {
			printf("skipped\n");
			continue;
		}
		test_cases[i].run_client(NULL);
		printf("ok\n");
	}
}

int main(int argc, char **argv)
{
	init_signals();

	for (;;) {
		int opt = getopt_long(argc, argv, optstring, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'l':
			list_tests(test_cases);
			break;
		case 's':
			skip_test(test_cases, ARRAY_SIZE(test_cases) - 1,
				  optarg);
			break;
		case '?':
		default:
			usage();
		}
	}

	run_loopback_tests(test_cases);
	return EXIT_SUCCESS;
}
