/*
    fsck.c -- Check the configuration files for problems
    Copyright (C) 2014-2021 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "crypto.h"
/* ecdsa.h/ecdsagen.h removed - QUIC only mode */
#include "fsck.h"
#include "names.h"
/* rsa.h/rsagen.h removed - QUIC only mode */
#include "tincctl.h"
#include "utils.h"

static bool ask_fix(void) {
	if(force) {
		return true;
	}

	if(!tty) {
		return false;
	}

again:
	fprintf(stderr, "Fix y/n? ");
	char buf[1024];

	if(!fgets(buf, sizeof(buf), stdin)) {
		tty = false;
		return false;
	}

	if(buf[0] == 'y' || buf[0] == 'Y') {
		return true;
	}

	if(buf[0] == 'n' || buf[0] == 'N') {
		return false;
	}

	goto again;
}

static void print_tinc_cmd(const char *argv0, const char *format, ...) {
	if(confbasegiven) {
		fprintf(stderr, "%s -c %s ", argv0, confbase);
	} else if(netname) {
		fprintf(stderr, "%s -n %s ", argv0, netname);
	} else {
		fprintf(stderr, "%s ", argv0);
	}

	va_list va;
	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	fputc('\n', stderr);
}

static int strtailcmp(const char *str, const char *tail) {
	size_t slen = strlen(str);
	size_t tlen = strlen(tail);

	if(tlen > slen) {
		return -1;
	}

	return memcmp(str + slen - tlen, tail, tlen);
}

static void check_conffile(const char *fname, bool server) {
	(void)server;

	FILE *f = fopen(fname, "r");

	if(!f) {
		fprintf(stderr, "ERROR: cannot read %s: %s\n", fname, strerror(errno));
		return;
	}

	char line[2048];
	int lineno = 0;
	bool skip = false;
	const int maxvariables = 50;
	int count[maxvariables];
	memset(count, 0, sizeof(count));

	while(fgets(line, sizeof(line), f)) {
		if(skip) {
			if(!strncmp(line, "-----END", 8)) {
				skip = false;
			}

			continue;
		} else {
			if(!strncmp(line, "-----BEGIN", 10)) {
				skip = true;
				continue;
			}
		}

		int len;
		char *variable, *value, *eol;
		variable = value = line;

		lineno++;

		eol = line + strlen(line);

		while(strchr("\t \r\n", *--eol)) {
			*eol = '\0';
		}

		if(!line[0] || line[0] == '#') {
			continue;
		}

		len = strcspn(value, "\t =");
		value += len;
		value += strspn(value, "\t ");

		if(*value == '=') {
			value++;
			value += strspn(value, "\t ");
		}

		variable[len] = '\0';

		bool found = false;

		for(int i = 0; variables[i].name; i++) {
			if(strcasecmp(variables[i].name, variable)) {
				continue;
			}

			found = true;

			if(variables[i].type & VAR_OBSOLETE) {
				fprintf(stderr, "WARNING: obsolete variable %s in %s line %d\n", variable, fname, lineno);
			}

			if(i < maxvariables) {
				count[i]++;
			}
		}

		if(!found) {
			fprintf(stderr, "WARNING: unknown variable %s in %s line %d\n", variable, fname, lineno);
		}

		if(!*value) {
			fprintf(stderr, "ERROR: no value for variable %s in %s line %d\n", variable, fname, lineno);
		}
	}

	for(int i = 0; variables[i].name && i < maxvariables; i++) {
		if(count[i] > 1 && !(variables[i].type & VAR_MULTIPLE)) {
			fprintf(stderr, "WARNING: multiple instances of variable %s in %s\n", variables[i].name, fname);
		}
	}

	if(ferror(f)) {
		fprintf(stderr, "ERROR: while reading %s: %s\n", fname, strerror(errno));
	}

	fclose(f);
}

int fsck(const char *argv0) {
#ifdef HAVE_MINGW
	int uid = 0;
#else
	uid_t uid = getuid();
#endif

	// Check that tinc.conf is readable.

	if(access(tinc_conf, R_OK)) {
		fprintf(stderr, "ERROR: cannot read %s: %s\n", tinc_conf, strerror(errno));

		if(errno == ENOENT) {
			fprintf(stderr, "No tinc configuration found. Create a new one with:\n\n");
			print_tinc_cmd(argv0, "init");
		} else if(errno == EACCES) {
			if(uid != 0) {
				fprintf(stderr, "You are currently not running tinc as root. Use sudo?\n");
			} else {
				fprintf(stderr, "Check the permissions of each component of the path %s.\n", tinc_conf);
			}
		}

		return 1;
	}

	char *name = get_my_name(true);

	if(!name) {
		fprintf(stderr, "ERROR: tinc cannot run without a valid Name.\n");
		return 1;
	}

	// Check for private keys.
	// TODO: use RSAPrivateKeyFile and Ed25519PrivateKeyFile variables if present.

	struct stat st;
	char fname[PATH_MAX];
	char dname[PATH_MAX];

	/* Legacy RSA key checking removed - QUIC only mode */

	/* ECDSA/RSA key checking removed - QUIC only mode uses TLS certificates (quic-cert.pem/quic-key.pem) */

	// Check whether scripts are executable

	struct dirent *ent;
	DIR *dir = opendir(confbase);

	if(!dir) {
		fprintf(stderr, "ERROR: cannot read directory %s: %s\n", confbase, strerror(errno));
		return 1;
	}

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down")) {
			continue;
		}

		strncpy(fname, ent->d_name, sizeof(fname));
		char *dash = strrchr(fname, '-');

		if(!dash) {
			continue;
		}

		*dash = 0;

		if(strcmp(fname, "host") && strcmp(fname, "subnet")) {
			static bool explained = false;
			fprintf(stderr, "WARNING: Unknown script %s" SLASH "%s found.\n", confbase, ent->d_name);

			if(!explained) {
				fprintf(stderr, "The only scripts in %s executed by tinc are:\n", confbase);
				fprintf(stderr, "host-up, host-down, subnet-up and subnet-down.\n");
				explained = true;
			}

			continue;
		}

		snprintf(fname, sizeof(fname), "%s" SLASH "%s", confbase, ent->d_name);

		if(access(fname, R_OK | X_OK)) {
			if(errno != EACCES) {
				fprintf(stderr, "ERROR: cannot access %s: %s\n", fname, strerror(errno));
				continue;
			}

			fprintf(stderr, "WARNING: cannot read and execute %s: %s\n", fname, strerror(errno));

			if(ask_fix()) {
				if(chmod(fname, 0755)) {
					fprintf(stderr, "ERROR: cannot change permissions on %s: %s\n", fname, strerror(errno));
				}
			}
		}
	}

	closedir(dir);

	snprintf(dname, sizeof(dname), "%s" SLASH "hosts", confbase);
	dir = opendir(dname);

	if(!dir) {
		fprintf(stderr, "ERROR: cannot read directory %s: %s\n", dname, strerror(errno));
		return 1;
	}

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down")) {
			continue;
		}

		strncpy(fname, ent->d_name, sizeof(fname));
		char *dash = strrchr(fname, '-');

		if(!dash) {
			continue;
		}

		*dash = 0;

		snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, ent->d_name);

		if(access(fname, R_OK | X_OK)) {
			if(errno != EACCES) {
				fprintf(stderr, "ERROR: cannot access %s: %s\n", fname, strerror(errno));
				continue;
			}

			fprintf(stderr, "WARNING: cannot read and execute %s: %s\n", fname, strerror(errno));

			if(ask_fix()) {
				if(chmod(fname, 0755)) {
					fprintf(stderr, "ERROR: cannot change permissions on %s: %s\n", fname, strerror(errno));
				}
			}
		}
	}

	closedir(dir);

	// Check for obsolete / unsafe / unknown configuration variables.

	check_conffile(tinc_conf, true);

	dir = opendir(dname);

	if(dir) {
		while((ent = readdir(dir))) {
			if(!check_id(ent->d_name)) {
				continue;
			}

			snprintf(fname, sizeof(fname), "%s" SLASH "hosts" SLASH "%s", confbase, ent->d_name);
			check_conffile(fname, false);
		}

		closedir(dir);
	}

	return 0;
}

