/**
   Copyright 2019 Mikhail Paulyshka

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**/

//stdlib
#include <fstream>

//nlohmann
#include "nlohmann/json.hpp"

//fakepdb
#include <functional>
#include <iostream>
#include <stdexcept>

#include "db.h"

namespace FakePDB::Data {
    DB::DB(){

    }

    DB::DB(std::filesystem::path &filepath) {
        load(filepath);
    }

    SectionGeneral& DB::General(){
        return _root.general;
    }

    SectionPE& DB::PE(){
        return _root.pe;
    }

    SegmentArray& DB::Segments(){
        return _root.segments;
    }

    std::vector<Export> &DB::Exports() {
        return _root.exports;
    }

    std::vector<Function> &DB::Functions() {
        return _root.functions;
    }

    std::vector<Name> &DB::Names() {
        return _root.names;
    }

    void DB::load(std::filesystem::path &filepath) {
        std::ifstream istream(filepath);
        if (!istream.is_open()) {
            throw std::runtime_error("cannot open JSON file: " + filepath.string());
        }

        nlohmann::json json;
        istream >> json;

        // IDA 9.x's Python API returns None in several places where 7.x returned "" (segment
        // class, names of functions IDA never displayed, ...). nlohmann's strict std::string
        // conversion throws on JSON null, which used to abort the whole run with no message.
        // Replace nulls with "" and report how many were found, rather than failing silently.
        size_t nulls_fixed = 0;
        std::function<void(nlohmann::json&)> sanitize = [&](nlohmann::json& node) {
            if (node.is_null()) {
                node = "";
                nulls_fixed++;
            } else if (node.is_structured()) {
                for (auto& child : node) {
                    sanitize(child);
                }
            }
        };
        sanitize(json);
        if (nulls_fixed != 0) {
            std::cerr << "warning: replaced " << nulls_fixed
                      << " null value(s) in the JSON with empty strings" << std::endl;
        }

        _root = json.get<Root>();

        //Labels
        for (auto &idaFunc : _root.functions) {
            for (auto &idaLabel : idaFunc.labels) {
                idaLabel.name = idaFunc.name + ":::" + idaLabel.name;
            }
        }
    }

    void DB::Save(std::filesystem::path &filepath) {
        nlohmann::json json = _root;
        std::ofstream file(filepath);
        file << std::setw(4) << json;
    }
}
