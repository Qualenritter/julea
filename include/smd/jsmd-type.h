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

#ifndef JULEA_SMD_TYPE_H
#define JULEA_SMD_TYPE_H

enum JSMDType
{
	J_SMD_TYPE_SINT32 = 0,
	J_SMD_TYPE_UINT32,
	J_SMD_TYPE_FLOAT32,
	J_SMD_TYPE_SINT64,
	J_SMD_TYPE_UINT64,
	J_SMD_TYPE_FLOAT64,
	J_SMD_TYPE_STRING,
	J_SMD_TYPE_BLOB,
	_J_SMD_TYPE_COUNT,
};
typedef enum JSMDType JSMDType;
enum JSMDOperator
{
	J_SMD_OPERATOR_LT = 0, //<
	J_SMD_OPERATOR_LE, //<=
	J_SMD_OPERATOR_GT, //>
	J_SMD_OPERATOR_GE, //>=
	J_SMD_OPERATOR_EQ, //=
	J_SMD_OPERATOR_NE, //!=
	_J_SMD_OPERATOR_COUNT,
};
typedef enum JSMDOperator JSMDOperator;

#endif
