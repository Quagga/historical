/*
 * Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2003 Vincent Jardin
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "str.h"

static void alloc_inc (int);
static void alloc_dec (int);
static void log_memstats(int log_priority);

#define ROUNDUP4(_size) (((_size+3) >> 2) << 2)
#if 0
static struct message mstr [] =
{
  { MTYPE_THREAD, "thread" },
  { MTYPE_THREAD_MASTER, "thread_master" },
  { MTYPE_VECTOR, "vector" },
  { MTYPE_VECTOR_INDEX, "vector_index" },
  { MTYPE_IF, "interface" },
  { 0, NULL },
};
#endif

extern struct mlist mlists[];

static const char *
lookup_memtype(int key)
{
  /* use global mlists */
  struct mlist *list;
  struct memory_list *list_elem;

  for (list = &mlists[0]; list != NULL; list++) 
    {
      for (list_elem = list[0].list; list_elem->index != -1; list_elem++) 
        if (list_elem->index == key) 
          return list_elem->format;
    }

  return "";
}


/* Fatal memory allocation error occured. */
static void
zerror (const char *fname, int type, size_t size)
{
  zlog_err ("%s : can't allocate memory for `%s' size %d: %s\n", 
	    fname, lookup_memtype(type), (int) size, safe_strerror(errno));
  log_memstats(LOG_WARNING);
  /* N.B. It might be preferable to call zlog_backtrace_sigsafe here, since
     that function should definitely be safe in an OOM condition.  But
     unfortunately zlog_backtrace_sigsafe does not support syslog logging at
     this time... */
  zlog_backtrace(LOG_WARNING);
  abort();
}

/* Memory allocation. */
void *
zmalloc (int type, size_t size)
{
  void *memory;

  memory = malloc (size);

  if (memory == NULL)
    zerror ("malloc", type, size);

  alloc_inc (type);

  return memory;
}

/* Memory allocation with num * size with cleared. */
void *
zcalloc (int type, size_t size)
{
  void *memory;

  memory = calloc (1, size);

  if (memory == NULL)
    zerror ("calloc", type, size);

  alloc_inc (type);

  return memory;
}

/* Memory reallocation. */
void *
zrealloc (int type, void *ptr, size_t size)
{
  void *memory;

  memory = realloc (ptr, size);
  if (memory == NULL)
    zerror ("realloc", type, size);
  return memory;
}

/* Memory free. */
void
zfree (int type, void *ptr)
{
  alloc_dec (type);
  free (ptr);
}

/* String duplication. */
char *
zstrdup (int type, const char *str)
{
  void *dup;

  dup = strdup (str);
  if (dup == NULL)
    zerror ("strdup", type, strlen (str));
  alloc_inc (type);
  return dup;
}

static char is_lib_debug_memory = 0;

void
memory_debug(char enable)
{
  is_lib_debug_memory = enable;
}

char
is_memory_debug(void)
{
  return is_lib_debug_memory;
}

#ifdef MEMORY_LOG
static struct 
{
  const char *name;
  unsigned long alloc;    /* Xalloc call counter  (number of currently allocated objects) */
  unsigned long malloc;   /* malloc call counter  (including fails)                       */
  unsigned long calloc;   /* calloc call counter  (including fails)                       */
  unsigned long realloc;  /* realloc call counter (including fails)                       */
  unsigned long free;     /* free call counter    (including fails)                       */
  unsigned long strdup;   /* strdup call counter  (including fails)                       */
  size_t alloced;         /* in bytes             (amount of currently allocated memory)  */
} mstat [MTYPE_MAX];

#define ZMEM_COOKIE1   0xcafedeca
#define ZMEM_COOKIE2   0xfecacade
#define ZMEM_COOKIE1_FREE   0xdeaddeca

/*
 * The header zmem_obj is added to each allocated memory buffers in order
 * to debug free and realloc, and to provide memory statistics.
 *
 *        ZMEM_OFFSET
 * <------------------------>
 * +----------+---+---------+-----------------------------------+---------+
 * | zmem_obj |pad| cookie1 | void *                            | cookie2 |
 * +----------+---+---------+-----------------------------------+---------+
 */
typedef struct {
	uint32_t val;
} __attribute__((packed)) zmem_cookie_t;

struct zmem_obj
{
  size_t size;
  int type;               /* MTYPE_XXX            */
  zmem_cookie_t *cookie1; /* must be ZMEM_COOKIE1 */
  void *mem;              /* the buffer           */
  zmem_cookie_t *cookie2; /* must be ZMEM_COOKIE2 */
  size_t crc;             /* = size | type | *cookie1 | *cookie2 */
};
#define ZMEM_OFFSET ROUNDUP4(sizeof(struct zmem_obj) + sizeof(zmem_cookie_t))
#define ZMEM_TRAILER sizeof(zmem_cookie_t)

#ifdef MEMORY_LOG_ASSERT
#define ZASSERT(e) assert(e)
#else
#define ZASSERT(e) do { \
  if (!(e))             \
    _zassert(__FILE__, __LINE__, #e); \
  } while (0);

static void
_zassert(const char *file, int line, const char *failedexpr)
{
  zlog_warn("Memory error %s: %d, %s", file, line, failedexpr);
}
#endif /*MEMORY_LOG_ASSERT*/

/*
 * Set the memory header
 */
static void
zobj_update(struct zmem_obj **pzobj, int type, void *memory, size_t size)
{
  struct zmem_obj *zobj = *pzobj;

  (*pzobj) = (struct zmem_obj *)memory;

  zobj = (struct zmem_obj *)memory;
  zobj->size    = size;
  zobj->type    = type;
  zobj->mem     = (void *)((caddr_t)memory + ZMEM_OFFSET);
  zobj->cookie1 = (zmem_cookie_t*)((caddr_t)zobj->mem - sizeof(zmem_cookie_t));
  zobj->cookie2 = (zmem_cookie_t*)((caddr_t)zobj->mem + size);
  zobj->cookie1->val = ZMEM_COOKIE1;
  zobj->cookie2->val = ZMEM_COOKIE2;
  zobj->crc = zobj->size | zobj->type | zobj->cookie1->val | zobj->cookie2->val;
}

/*
 * Check the memory's header
 */
static void
zobj_assert(struct zmem_obj * zobj)
{
  size_t crc;

  /* detect double free */
  ZASSERT(zobj->cookie1->val != ZMEM_COOKIE1_FREE);

  /* detect bad pointer or buffer overflow */
  ZASSERT(zobj->cookie1->val == ZMEM_COOKIE1);

  /* detect buffer overflow */
  ZASSERT(zobj->cookie2->val == ZMEM_COOKIE2);

 /* detect invalid type */
  ZASSERT(0 < zobj->type);
  ZASSERT(zobj->type < MTYPE_MAX);

  /* check crc */
  crc = zobj->size | zobj->type | zobj->cookie1->val | zobj->cookie2->val;
  ZASSERT(zobj->crc == crc);
}

static void
mtype_log (char *func, void *memory, const char *file, int line, int type)
{
  if (is_lib_debug_memory)
    zlog_debug ("%s: %s %p %s %d", func, lookup_memtype(type), memory, file, line);
}

void *
mtype_zmalloc (const char *file, int line, int type, size_t size)
{
  void *memory;
  struct zmem_obj *zobj;

  ZASSERT(type);

  mstat[type].malloc++;

  memory = zmalloc (type, size + ZMEM_OFFSET + ZMEM_TRAILER);

  if (memory == NULL)
    return NULL;

  mstat[type].alloced += size;

  zobj_update(&zobj, type, memory, size);

  mtype_log ("zmalloc", zobj->mem, file, line, zobj->type);

  return zobj->mem;
}

void *
mtype_zcalloc (const char *file, int line, int type, size_t size)
{
  void *memory;
  struct zmem_obj *zobj;

  ZASSERT(type);

  mstat[type].calloc++;

  memory = zcalloc (type, size + ZMEM_OFFSET + ZMEM_TRAILER);

  if (memory == NULL)
    return NULL;

  mstat[type].alloced += size;

  zobj_update(&zobj, type, memory, size);
 
  mtype_log ("xcalloc", zobj->mem, file, line, zobj->type);

  return zobj->mem;
}

void *
mtype_zrealloc (const char *file, int line, int type, void *ptr, size_t size)
{
  void *memory;
  struct zmem_obj *zobj;

  ZASSERT(type);

  ZASSERT(ptr);

  /* Retrieve the header of the memory buffer */
  zobj = (struct zmem_obj *)((caddr_t)ptr - ZMEM_OFFSET);

  zobj_assert(zobj);

  /* A potato should not become a cow */
  if (zobj->type != type) {
    /* XXX: bad hack in order to be more tolerant */
    zlog_warn("xrealloc: type changed from `%s' to `%s' %s:%d",
              lookup_memtype(zobj->type),
              lookup_memtype(type), file, line);
    mstat[zobj->type].alloced -= zobj->size;
    alloc_dec(zobj->type);
    alloc_inc(type);
    zobj->type = type;
  } else {
    mstat[type].alloced -= zobj->size;
  }

  /* Realloc need before allocated pointer. */
  mstat[type].realloc++;

  memory = zrealloc (type, zobj, size + ZMEM_OFFSET + ZMEM_TRAILER);

  if (memory == NULL)
    return NULL;

  mstat[type].alloced += size;

  zobj_update(&zobj, type, memory, size);

  mtype_log ("xrealloc", zobj->mem, file, line, zobj->type);

  return zobj->mem;
}

/* Important function. */
void 
mtype_zfree (const char *file, int line, int type, void *ptr)
{
  struct zmem_obj *zobj;

  ZASSERT(type);

  ZASSERT(ptr);

  /* Retrieve the header of the memory buffer */
  zobj = (struct zmem_obj *)((caddr_t)ptr - ZMEM_OFFSET);

  zobj_assert(zobj);

  /* A potato should not become a cow */
  if (zobj->type != type) {
    /* XXX */
    zlog_warn("xfree: type changed from '%s' to '%s' %s:%d",
              lookup_memtype(zobj->type),
              lookup_memtype(type), file, line);
    mstat[zobj->type].alloced -= zobj->size;
    alloc_dec(zobj->type);
    alloc_inc(type);
    zobj->type = type;
  } else {
    mstat[type].alloced -= zobj->size;
  }

  mstat[type].free++;

  /* mark buffer as free, to detect double free */
  zobj->cookie1->val = ZMEM_COOKIE1_FREE;

  mtype_log ("xfree", zobj->mem, file, line, zobj->type);

  zfree (type, (void *)zobj);
}

char *
mtype_zstrdup (const char *file, int line, int type, const char *str)
{
  char *memory;
  struct zmem_obj *zobj;
  size_t size;

  ZASSERT(type);

  size = strlen(str) + 1;
  mstat[type].strdup++;

  /*
   * zstrdup, strdup are rewritten because they are not compatible
   * with our memory support (zmem_obj).
   */
  memory = zmalloc (type, size + ZMEM_OFFSET + ZMEM_TRAILER);

  if (memory == NULL) {
    zerror ("strdup", type, size);
    return NULL;
  }

  mstat[type].alloced += size;

  zobj_update(&zobj, type, memory, size);

  strlcpy((char *)zobj->mem, str, size);

  mtype_log ("xstrdup", zobj->mem, file, line, zobj->type);

  return (char *)zobj->mem;
}

static int
unit_div(size_t size)
{
  uint8_t i;

  if (size == 0)
    return 0;

  for (i = 0; size != 0; size /= 1024, i++)
    ;

  return i-1;
}

static const char unit_str[][4] =
  { "B", "KB", "MB"     , "GB"          , "GB"          ,
    "??" };

static const size_t unit_1024[] =
  { 1,   1024, 1024*1024, 1024*1024*1024, 1024*1024*1024,
    1 };

#else
static struct 
{
  char *name;
  unsigned long alloc;
} mstat [MTYPE_MAX];
#endif /* MEMORY_LOG */

/* Increment allocation counter. */
static void
alloc_inc (int type)
{
  mstat[type].alloc++;
}

/* Decrement allocation counter. */
static void
alloc_dec (int type)
{
  mstat[type].alloc--;
}

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

static void
log_memstats(int pri)
{
  struct mlist *ml;

  for (ml = mlists; ml->list; ml++)
    {
      struct memory_list *m;

      zlog (NULL, pri, "Memory utilization in module %s:", ml->name);
      for (m = ml->list; m->index >= 0; m++)
	if (m->index && mstat[m->index].alloc)
	  zlog (NULL, pri, "  %-30s: %10ld", m->format, mstat[m->index].alloc);
    }
}


static struct memory_list memory_list_separator[] =
{
  { 0 },
  {-1 }
};

static void
show_memory_vty (struct vty *vty, struct memory_list *list, int protocol)
{
  struct memory_list *m;

  /* Print the name of the protocol */
  if (protocol && zlog_default) {
    vty_out (vty, "=== %s ===%s",
             zlog_proto_names[zlog_default->protocol], VTY_NEWLINE);
#ifdef MEMORY_LOG
    vty_out (vty,   "     Object                           Used   Bytes   Called/Destroyed%s", VTY_NEWLINE);
#endif /* MEMORY_LOG */
#if 0
                     12345678901234567890123456789012345678901234567890123456789
                              1         2         3         4         5
#endif
  }

  for (m = list; m->index >= 0; m++)
    if (m->index == 0)
      vty_out (vty, "---------------------------------------%s", VTY_NEWLINE);
    else
#ifdef MEMORY_LOG
    {
      int unit;
      unit = unit_div(mstat[m->index].alloced);

      vty_out (vty, "%-30s: %10ld %5d%2s %4ld/%ld%s", lookup_memtype(m->index),
                    mstat[m->index].alloc,
                    mstat[m->index].alloced / unit_1024[unit],
                    unit_str[unit],
                    mstat[m->index].malloc + mstat[m->index].calloc
                    + mstat[m->index].realloc + mstat[m->index].strdup,
                    mstat[m->index].free,
                    VTY_NEWLINE);
    }
#else
    {
      vty_out (vty, "%-30s: %10ld%s", m->format, mstat[m->index].alloc, VTY_NEWLINE);
    }
#endif /* MEMORY_LOG */
}

DEFUN (show_memory_all,
       show_memory_all_cmd,
       "show memory all",
       "Show running system information\n"
       "Memory statistics\n"
       "All memory statistics\n")
{
  show_memory_vty (vty, memory_list_lib, 1);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_zebra, 0);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_rip, 0);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_ripng, 0);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_ospf, 0);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_ospf6, 0);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_isis, 0);
  show_memory_vty (vty, memory_list_separator, 0);
  show_memory_vty (vty, memory_list_bgp, 0);

  return CMD_SUCCESS;
}

ALIAS (show_memory_all,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")

DEFUN (show_memory_lib,
       show_memory_lib_cmd,
       "show memory lib",
       SHOW_STR
       "Memory statistics\n"
       "Library memory\n")
{
  show_memory_vty (vty, memory_list_lib, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_zebra,
       show_memory_zebra_cmd,
       "show memory fib",
       SHOW_STR
       "Memory statistics\n"
       "FIB memory\n")
{
  show_memory_vty (vty, memory_list_zebra, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_rip,
       show_memory_rip_cmd,
       "show memory rip",
       SHOW_STR
       "Memory statistics\n"
       "RIP memory\n")
{
  show_memory_vty (vty, memory_list_rip, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_ripng,
       show_memory_ripng_cmd,
       "show memory ripng",
       SHOW_STR
       "Memory statistics\n"
       "RIPng memory\n")
{
  show_memory_vty (vty, memory_list_ripng, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_bgp,
       show_memory_bgp_cmd,
       "show memory bgp",
       SHOW_STR
       "Memory statistics\n"
       "BGP memory\n")
{
  show_memory_vty (vty, memory_list_bgp, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_ospf,
       show_memory_ospf_cmd,
       "show memory ospf",
       SHOW_STR
       "Memory statistics\n"
       "OSPF memory\n")
{
  show_memory_vty (vty, memory_list_ospf, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_ospf6,
       show_memory_ospf6_cmd,
       "show memory ospf6",
       SHOW_STR
       "Memory statistics\n"
       "OSPF6 memory\n")
{
  show_memory_vty (vty, memory_list_ospf6, 1);
  return CMD_SUCCESS;
}

DEFUN_NOSH (show_memory_isis,
       show_memory_isis_cmd,
       "show memory isis",
       SHOW_STR
       "Memory statistics\n"
       "ISIS memory\n")
{
  show_memory_vty (vty, memory_list_isis, 1);
  return CMD_SUCCESS;
}


void
memory_init (void)
{
  install_element (VIEW_NODE, &show_memory_cmd);
  install_element (VIEW_NODE, &show_memory_all_cmd);
  install_element (VIEW_NODE, &show_memory_lib_cmd);
  install_element (VIEW_NODE, &show_memory_zebra_cmd);
  install_element (VIEW_NODE, &show_memory_rip_cmd);
  install_element (VIEW_NODE, &show_memory_ripng_cmd);
  install_element (VIEW_NODE, &show_memory_bgp_cmd);
  install_element (VIEW_NODE, &show_memory_ospf_cmd);
  install_element (VIEW_NODE, &show_memory_ospf6_cmd);
  install_element (VIEW_NODE, &show_memory_isis_cmd);


  install_element (ENABLE_NODE, &show_memory_cmd);
  install_element (ENABLE_NODE, &show_memory_all_cmd);
  install_element (ENABLE_NODE, &show_memory_lib_cmd);
  install_element (ENABLE_NODE, &show_memory_zebra_cmd);
  install_element (ENABLE_NODE, &show_memory_rip_cmd);
  install_element (ENABLE_NODE, &show_memory_ripng_cmd);
  install_element (ENABLE_NODE, &show_memory_bgp_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf6_cmd);
  install_element (ENABLE_NODE, &show_memory_isis_cmd);

}
