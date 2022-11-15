// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Bobby Eshleman <bobby.eshleman@bytedance.com>
 *
 * Based off of net/unix/unix_bpf.c
 */

#include <linux/bpf.h>
#include <linux/module.h>
#include <linux/skmsg.h>
#include <linux/socket.h>
#include <net/af_vsock.h>
#include <net/sock.h>

#define vsock_sk_has_data(__sk, __psock)				\
		({	!skb_queue_empty(&__sk->sk_receive_queue) ||	\
			!skb_queue_empty(&__psock->ingress_skb) ||	\
			!list_empty(&__psock->ingress_msg);		\
		})

static struct proto *vsock_dgram_prot_saved __read_mostly;
static DEFINE_SPINLOCK(vsock_dgram_prot_lock);
static struct proto vsock_dgram_bpf_prot;

static bool vsock_has_data(struct vsock_sock *vsk, struct sk_psock *psock)
{
	struct sock *sk = sk_vsock(vsk);
	s64 ret;

	ret = vsock_connectible_has_data(vsk);
	if (ret > 0)
		return true;

	return vsock_sk_has_data(sk, psock);
}

static int vsock_msg_wait_data(struct sock *sk, struct sk_psock *psock, long timeo)
{
	struct vsock_sock *vsk;
	int err;

	DEFINE_WAIT(wait);

	vsk = vsock_sk(sk);
	err = 0;

	while (vsock_has_data(vsk, psock)) {
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

		if (sk->sk_err != 0 ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    (vsk->peer_shutdown & SEND_SHUTDOWN)) {
			break;
		}

		if (timeo == 0) {
			err = -EAGAIN;
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		} else if (timeo == 0) {
			err = -EAGAIN;
			break;
		}
	}

	finish_wait(sk_sleep(sk), &wait);

	if (err)
		return err;

	return 0;
}

static int vsock_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	int err;
	struct socket *sock = sk->sk_socket;

	if (sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_SEQPACKET)
		err = vsock_connectible_recvmsg(sock, msg, len, flags);
	else
		err = vsock_dgram_recvmsg(sock, msg, len, flags);

	return err;
}

static int vsock_bpf_recvmsg(struct sock *sk, struct msghdr *msg,
			     size_t len, int flags, int *addr_len)
{
	int copied;
	struct sk_psock *psock;

	lock_sock(sk);
	psock = sk_psock_get(sk);
	if (unlikely(!psock)) {
		release_sock(sk);
		return vsock_recvmsg(sk, msg, len, flags);
	}

	if (vsock_has_data(vsock_sk(sk), psock) && sk_psock_queue_empty(psock)) {
		sk_psock_put(sk, psock);
		release_sock(sk);
		return vsock_recvmsg(sk, msg, len, flags);
	}

msg_bytes_ready:
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	if (!copied) {
		long timeo;
		int data;

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		data = vsock_msg_wait_data(sk, psock, timeo);
		if (data) {
			if (!sk_psock_queue_empty(psock))
				goto msg_bytes_ready;
			sk_psock_put(sk, psock);
			release_sock(sk);
			return vsock_recvmsg(sk, msg, len, flags);
		}
		copied = -EAGAIN;
	}
	sk_psock_put(sk, psock);
	release_sock(sk);

	return copied;
}

/* Copy of original proto with updated sock_map methods */
static struct proto vsock_dgram_bpf_prot = {
	.close = sock_map_close,
	.recvmsg = vsock_bpf_recvmsg,
	.sock_is_readable = sk_msg_is_readable,
	.unhash = sock_map_unhash,
};

static void vsock_dgram_bpf_rebuild_protos(struct proto *prot, const struct proto *base)
{
	*prot        = *base;
	prot->close  = sock_map_close;
	prot->recvmsg = vsock_bpf_recvmsg;
	prot->sock_is_readable = sk_msg_is_readable;
}

static void vsock_dgram_bpf_check_needs_rebuild(struct proto *ops)
{
	if (unlikely(ops != smp_load_acquire(&vsock_dgram_prot_saved))) {
		spin_lock_bh(&vsock_dgram_prot_lock);
		if (likely(ops != vsock_dgram_prot_saved)) {
			vsock_dgram_bpf_rebuild_protos(&vsock_dgram_bpf_prot, ops);
			smp_store_release(&vsock_dgram_prot_saved, ops);
		}
		spin_unlock_bh(&vsock_dgram_prot_lock);
	}
}

int vsock_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
	if (restore) {
		sk->sk_write_space = psock->saved_write_space;
		sock_replace_proto(sk, psock->sk_proto);
		return 0;
	}

	vsock_dgram_bpf_check_needs_rebuild(psock->sk_proto);
	sock_replace_proto(sk, &vsock_dgram_bpf_prot);
	return 0;
}

void __init vsock_bpf_build_proto(void)
{
	vsock_dgram_bpf_rebuild_protos(&vsock_dgram_bpf_prot, &vsock_proto);
}
