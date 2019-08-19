/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2019 Benjamin Warnke
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

#include <hdf5.h>
#include <H5PLextern.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>

int
main (int argc, char** argv)
{
	(void)argc;
	(void)argv;

	hid_t julea_vol_id;
	printf("XXX 1\n");
	julea_vol_id = H5VLregister_connector_by_name("julea", H5P_DEFAULT);
	printf("XXX 2\n");
	H5VLinitialize(julea_vol_id, H5P_DEFAULT);
	printf("XXX 3\n");
	H5VLterminate(julea_vol_id);
	printf("XXX 4\n");
        H5VLunregister_connector(julea_vol_id);
	printf("XXX 5\n");
	return 0;
}
