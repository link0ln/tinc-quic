#ifndef TINC_CONFIG_TEMPLATE_H
#define TINC_CONFIG_TEMPLATE_H

/*
    config_template.h -- Generate default tinc.conf template
    Copyright (C) 2025 Tinc VPN Project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <stdbool.h>

/*
 * Generate default tinc.conf with all options documented.
 * Required options are set to sensible defaults.
 * Optional options are commented out with descriptions.
 *
 * @param filepath  Full path to the tinc.conf file to create
 * @param node_name Name of this node (required)
 * @return true on success, false on failure
 */
bool generate_default_config(const char *filepath, const char *node_name);

/*
 * Check if tinc.conf exists in the given confbase directory.
 *
 * @param confbase Path to the tinc configuration directory
 * @return true if tinc.conf exists, false otherwise
 */
bool config_file_exists(const char *confbase);

/*
 * Ensure required configuration directories exist.
 * Creates confbase, hosts, and cache directories.
 *
 * @param confbase Path to the tinc configuration directory
 * @return true on success, false on failure
 */
bool ensure_config_dirs(const char *confbase);

#endif
