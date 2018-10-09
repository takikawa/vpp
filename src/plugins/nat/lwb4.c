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
#include <nat/lwb4_dpo.h>
#include <vnet/fib/fib_table.h>

lwb4_main_t lwb4_main;

void
lwb4_init (vlib_main_t * vm)
{
  lwb4_main_t *dm = &lwb4_main;
  vlib_thread_registration_t *tr;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *p;
  lwb4_per_thread_data_t *td;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128 << 20;
  u32 b4_buckets = 128;
  u32 b4_memory_size = 64 << 20;

  dm->first_worker_index = 0;
  dm->num_workers = 0;

  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  dm->num_workers = tr->count;
	  dm->first_worker_index = tr->first_index;
	}
    }

  /* FIXME: modify to fit psid range */
  if (dm->num_workers)
    dm->port_per_thread = (0xffff - 1024) / dm->num_workers;
  else
    dm->port_per_thread = 0xffff - 1024;

  vec_validate (dm->per_thread_data, tm->n_vlib_mains - 1);

  /* *INDENT-OFF* */
  vec_foreach (td, dm->per_thread_data)
    {
      clib_bihash_init_24_8 (&td->in2out, "in2out", translation_buckets,
                             translation_memory_size);

      clib_bihash_init_8_8 (&td->out2in, "out2in", translation_buckets,
                            translation_memory_size);

      clib_bihash_init_16_8 (&td->b4_hash, "b4s", b4_buckets, b4_memory_size);
    }
  /* *INDENT-ON* */

  lwb4_dpo_module_init ();
}

int
lwb4_set_aftr_ip6_addr (lwb4_main_t * dm, ip6_address_t * addr)
{
  dpo_id_t dpo = DPO_INVALID;

  lwb4_ce_dpo_create (DPO_PROTO_IP4, 0, &dpo);
  fib_prefix_t pfx = {
    proto = FIB_PROTOCOL_IP4,
    len = 0,
    addr.ip4.as_u32 = 0,
  };
  fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
  	       fib_ENTRY_FLAG_EXCLUSIVE, &dpo);

  dpo_reset (&dpo);

  dm->aftr_ip6_addr.as_u64[0] = addr->as_u64[0];
  dm->aftr_ip6_addr.as_u64[1] = addr->as_u64[1];
  return 0;
}

int
lwb4_set_aftr_ip4_addr (lwb4_main_t * dm, ip4_address_t * addr)
{
  dm->aftr_ip4_addr.as_u32 = addr->as_u32;
  return 0;
}

int
lwb4_set_b4_params (lwb4_main_t * dm, ip6_address_t * ip6_addr,
                    ip4_address_t * ip4_addr, /* FIXME: psid */)
{
  dpo_id_t dpo = DPO_INVALID;

  lwb4_ce_dpo_create (DPO_PROTO_IP6, 0, &dpo);
  fib_prefix_t pfx = {
	  .fp_proto = FIB_PROTOCOL_IP6,
	  .fp_len = 128,
	  .fp_addr.ip6.as_u64[0] = ip6_addr->as_u64[0],
	  .fp_addr.ip6.as_u64[1] = ip6_addr->as_u64[1],
  };
  fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
                                   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  dpo_reset (&dpo);

  dm->b4_ip6_addr.as_u64[0] = ip6_addr->as_u64[0];
  dm->b4_ip6_addr.as_u64[1] = ip6_addr->as_u64[1];

  dm->b4_ip4_addr.as_u32 = ip4_addr->as_u32;

  dm->snat_addr.addr = ip4_addr;
  dm->snat_addr.fib_index = 0; /* FIXME: ?? */
  /* FIXME: macrology to set up busy_##n##_ports here */
  dm->addr_pool = 0;
  vec_add1(dm->addr_pool, dm->snat_addr)

  return 0;
}

u8 *
format_lwb4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lwb4_trace_t *t = va_arg (*args, lwb4_trace_t *);

  s =
    format (s, "next index %d, session %d", t->next_index, t->session_index);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
