/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once
#include <sdbusplus/bus.hpp>
#include <cstdint>
#include <limits>
#include <boost/variant.hpp>
namespace ipmi
{

using DbusVariant =
    sdbusplus::message::variant<std::string, bool, uint8_t, uint16_t, int16_t,
                                uint32_t, int32_t, uint64_t, int64_t, double>;

struct DoubleVisitor : public boost::static_visitor<double>
{
    template <typename T> double operator()(const T &t) const
    {
        return static_cast<double>(t);
    }
};

template <>
inline double DoubleVisitor::operator()<std::string>(const std::string &s) const
{
    throw std::invalid_argument("Cannot translate string to double");
}
template <> inline double DoubleVisitor::operator()<bool>(const bool &b) const
{
    throw std::invalid_argument("Cannot translate bool to double");
}
} // namespace ipmi
