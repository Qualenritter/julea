/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2010-2019 Michael Kuhn
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file
 **/

#ifndef JULEA_INTERNAL_H
#define JULEA_INTERNAL_H

#if !defined(JULEA_H) && !defined(JULEA_COMPILATION)
#error "Only <julea.h> can be included directly."
#endif

#include <glib.h>

#include <core/jtrace-internal.h>

G_BEGIN_DECLS

#define J_CRITICAL(format, ...) g_critical("%s:%s: " format, G_STRLOC, G_STRFUNC, ##__VA_ARGS__);
#ifdef JULEA_DEBUG
#define J_WARNING(format, ...) g_warning("%s:%s: " format, G_STRLOC, G_STRFUNC, ##__VA_ARGS__);
#define J_INFO(format, ...) g_info("%s:%s: " format, G_STRLOC, G_STRFUNC, ##__VA_ARGS__);
#define J_DEBUG(format, ...) g_debug("%s:%s: " format, G_STRLOC, G_STRFUNC, ##__VA_ARGS__);
#else
#define J_WARNING(format, ...)
#define J_INFO(format, ...)
#define J_DEBUG(format, ...)
#endif
/* FIXME j_sync() for benchmarks */

G_END_DECLS

#endif
