/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <nat/lwb4.h>
#include <nat/nat_inlines.h>

vlib_node_registration_t lwb4_out2in_node;

typedef enum
{
  LWB4_OUT2IN_NEXT_IP4_LOOKUP,
  LWB4_OUT2IN_NEXT_IP6_LOOKUP,
  LWB4_OUT2IN_NEXT_DROP,
  LWB4_OUT2IN_N_NEXT,
} lwb4_out2in_next_t;

static char *lwb4_out2in_error_strings[] = {
#define _(sym,string) string,
  foreach_lwb4_error
#undef _
};

static inline u32
lwb4_icmp_out2in (lwb4_main_t * dm, ip4_header_t * ip4,
		    lwb4_session_t ** sp, u32 next, u8 * error,
		    u32 thread_index)
{
  lwb4_session_t *s = 0;
  icmp46_header_t *icmp = ip4_next_header (ip4);
  clib_bihash_kv_8_8_t kv, value;
  snat_session_key_t key;
  u32 n = next;
  icmp_echo_header_t *echo;
  u32 new_addr, old_addr;
  u16 old_id, new_id;
  ip_csum_t sum;

  echo = (icmp_echo_header_t *) (icmp + 1);

  if (icmp_is_error_message (icmp) || (icmp->type != ICMP4_echo_reply))
    {
      n = LWB4_OUT2IN_NEXT_DROP;
      *error = LWB4_ERROR_BAD_ICMP_TYPE;
      goto done;
    }

  key.addr = ip4->dst_address;
  key.port = echo->identifier;
  key.protocol = SNAT_PROTOCOL_ICMP;
  key.fib_index = 0;
  kv.key = key.as_u64;

  if (clib_bihash_search_8_8
      (&dm->per_thread_data[thread_index].out2in, &kv, &value))
    {
      next = LWB4_OUT2IN_NEXT_DROP;
      *error = LWB4_ERROR_NO_TRANSLATION;
      goto done;
    }
  else
    {
      s =
	pool_elt_at_index (dm->per_thread_data[thread_index].sessions,
			   value.value);
    }

  old_id = echo->identifier;
  echo->identifier = new_id = s->in2out.port;
  sum = icmp->checksum;
  sum = ip_csum_update (sum, old_id, new_id, icmp_echo_header_t, identifier);
  icmp->checksum = ip_csum_fold (sum);

  old_addr = ip4->dst_address.as_u32;
  ip4->dst_address = s->in2out.addr;
  new_addr = ip4->dst_address.as_u32;

  sum = ip4->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip4->checksum = ip_csum_fold (sum);

done:
  *sp = s;
  return n;
}

static uword
lwb4_out2in_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  lwb4_out2in_next_t next_index;
  vlib_node_runtime_t *error_node;
  u32 thread_index = vm->thread_index;
  f64 now = vlib_time_now (vm);
  lwb4_main_t *dm = &lwb4_main;

  error_node = vlib_node_get_runtime (vm, lwb4_out2in_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;


  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = LWB4_OUT2IN_NEXT_IP4_LOOKUP;
	  u8 error0 = LWB4_ERROR_OUT2IN;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 proto0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  clib_bihash_kv_8_8_t kv0, value0;
	  snat_session_key_t key0;
	  lwb4_session_t *s0 = 0;
	  ip_csum_t sum0;
	  u32 new_addr0, old_addr0;
	  u16 new_port0, old_port0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (b0);
	  proto0 = ip_proto_to_snat_proto (ip60->protocol);

	  if (PREDICT_FALSE (ip60->protocol != IP_PROTOCOL_IP_IN_IP))
	    {
	      if (ip60->protocol == IP_PROTOCOL_ICMP6)
          {
            /*next0 = LWB4_OUT2IN_NEXT_IP6_ICMP;*/
            goto trace0;
          }
	      error0 = LWB4_ERROR_BAD_IP6_PROTOCOL;
	      next0 = LWB4_OUT2IN_NEXT_DROP;
	      goto trace0;
	    }

	  ip40 = vlib_buffer_get_current (b0) + sizeof (ip6_header_t);
	  proto0 = ip_proto_to_snat_proto (ip40->protocol);

	  if (PREDICT_FALSE (proto0 == ~0))
	    {
	      error0 = LWB4_ERROR_UNSUPPORTED_PROTOCOL;
	      /* next0 = LWB4_DECAP_NEXT_DROP; */
	      goto trace0;
	    }

	  ip40->tos =
	    (clib_net_to_host_u32
	     (ip60->ip_version_traffic_class_and_flow_label) & 0x0ff00000) >>
	    20;
	  vlib_buffer_advance (b0, sizeof (ip6_header_t));

    /* FIXME: handle ICMPv6 before decap or ICMPv4 after? */
    /*
	  if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
	    {
	      next0 =
		lwb4_icmp_out2in (dm, ip40, &s0, next0, &error0,
				    thread_index);
	      if (PREDICT_FALSE (next0 == LWB4_OUT2IN_NEXT_DROP))
		goto trace0;

	      goto encap0;
	    }
    */

	  udp0 = ip4_next_header (ip40);
	  tcp0 = (tcp_header_t *) udp0;

	  key0.addr = ip40->dst_address;
	  key0.port = udp0->dst_port;
	  key0.protocol = proto0;
	  key0.fib_index = 0;
	  kv0.key = key0.as_u64;

	  if (clib_bihash_search_8_8
	      (&dm->per_thread_data[thread_index].out2in, &kv0, &value0))
	    {
	      next0 = LWB4_OUT2IN_NEXT_DROP;
	      error0 = LWB4_ERROR_NO_TRANSLATION;
	      goto trace0;
	    }
	  else
	    {
	      s0 =
		pool_elt_at_index (dm->per_thread_data[thread_index].sessions,
				   value0.value);
	    }

	  old_addr0 = ip40->dst_address.as_u32;
	  ip40->dst_address = s0->in2out.addr;
	  new_addr0 = ip40->dst_address.as_u32;

	  sum0 = ip40->checksum;
	  sum0 =
	    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			    dst_address);
	  ip40->checksum = ip_csum_fold (sum0);

	  if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
	    {
	      old_port0 = tcp0->dst_port;
	      tcp0->dst_port = s0->in2out.port;
	      new_port0 = tcp0->dst_port;

	      sum0 = tcp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				dst_address);
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				length);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      old_port0 = udp0->dst_port;
	      udp0->dst_port = s0->in2out.port;
	      udp0->checksum = 0;
	    }

	  /* Accounting */
	  s0->last_heard = now;
	  s0->total_pkts++;
	  s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lwb4_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (s0)
		t->session_index =
		  s0 - dm->per_thread_data[thread_index].sessions;
	    }

	  b0->error = error_node->errors[error0];

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lwb4_out2in_node) = {
  .function = lwb4_out2in_node_fn,
  .name = "lwb4-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_lwb4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (lwb4_out2in_error_strings),
  .error_strings = lwb4_out2in_error_strings,
  .n_next_nodes = LWB4_OUT2IN_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [LWB4_OUT2IN_NEXT_DROP] = "error-drop",
    [LWB4_OUT2IN_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [LWB4_OUT2IN_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (lwb4_out2in_node, lwb4_out2in_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
