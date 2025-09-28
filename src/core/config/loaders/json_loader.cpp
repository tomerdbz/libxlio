/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_loader.h"
#include "core/config/config_strings.h"
#include "core/config/json_object_handle.h"
#include "core/config/json_utils.h"
#include "core/util/xlio_exception.h"
#include <fstream>

json_loader::json_loader(const char *file_path)
    : loader(file_path)
{
    std::ifstream ifs(m_source.c_str());
    if (!ifs.good()) {
        throw_xlio_exception("Cannot open file: " + m_source);
    }
}

std::map<std::string, std::experimental::any> json_loader::load_all() &
{
    if (!m_data.empty()) {
        return m_data;
    }

    json_object *raw_obj = parse_json_file(m_source);
    json_object_handle root_obj(raw_obj);

    if (json_object_get_type(root_obj.get()) != json_type_object) {
        throw_xlio_exception("Top-level JSON is not an object: " + m_source);
    }

    process_json_object(config_strings::misc::EMPTY_STRING, root_obj.get());
    return m_data;
}

void json_loader::process_json_object(const std::string &prefix, json_object *obj)
{
    json_object_object_foreach(obj, key, value)
    {
        std::string key_str(key);
        if (key_str.find('.') != std::string::npos) {
            throw_xlio_exception("Key cannot contain dots: " + key_str);
        }

        std::string current_key =
            prefix.empty() ? std::move(key_str) : (prefix + config_strings::misc::DOT + key_str);

        json_type type = json_object_get_type(value);
        if (type == json_type_object) {
            // Recursively process nested objects
            process_json_object(current_key, value);
        } else {
            // Store non-object values directly using centralized conversion
            m_data[current_key] = json_utils::to_any_value(value);
        }
    }
}

json_object *json_loader::parse_json_file(const std::string &file_path)
{
    std::ifstream file_stream(file_path.c_str(), std::ios::in | std::ios::binary);
    if (!file_stream.is_open()) {
        throw_xlio_exception("Cannot open file: " + file_path);
    }

    file_stream.seekg(0, std::ios::end);
    std::streamsize size = file_stream.tellg();
    file_stream.seekg(0, std::ios::beg);

    std::vector<char> buffer(static_cast<size_t>(size), 0);
    if (!file_stream.read(buffer.data(), size)) {
        throw_xlio_exception("Failed to read JSON file: " + file_path);
    }

    json_tokener *tokener = json_tokener_new_ex(JSON_TOKENER_DEFAULT_DEPTH);
    if (!tokener) {
        throw_xlio_exception("Failed to create JSON tokener");
    }
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT); // Set strict mode after creation
    json_object *raw_obj =
        json_tokener_parse_ex(tokener, buffer.data(), static_cast<int>(buffer.size()));
    enum json_tokener_error tokener_err = json_tokener_get_error(tokener);
    json_tokener_free(tokener);

    if (!raw_obj) {
        std::string error_msg = "Failed to parse JSON file: " + file_path;
        error_msg += "\nValidate " + file_path + " with a JSON validator.";
        error_msg += "\nJSON parse error: ";
        error_msg += json_tokener_error_desc(tokener_err);
        throw_xlio_exception(error_msg);
    }

    return raw_obj;
}
