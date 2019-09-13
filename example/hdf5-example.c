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

int main()
{
	hid_t julea_vol_id;
	hid_t fapl;
	hid_t file;

	// initialize vol-plugin

	julea_vol_id = H5VLregister_connector_by_name("julea", H5P_DEFAULT);
	H5VLinitialize(julea_vol_id, H5P_DEFAULT);

	// create / open file

	fapl = H5Pcreate(H5P_FILE_ACCESS);
	H5Pset_vol(fapl, julea_vol_id, NULL);
	file = H5Fcreate("julea.h5", H5F_ACC_TRUNC, H5P_DEFAULT, fapl);

	// XXX do sth with file

	// close file

	H5Fclose(file);
	H5Pclose(fapl);

	// finalize vol-plugin

	H5VLterminate(julea_vol_id);
	H5VLunregister_connector(julea_vol_id);
	return 0;
}
