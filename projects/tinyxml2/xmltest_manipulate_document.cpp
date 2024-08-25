/* Copyright 2024 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "tinyxml2/tinyxml2.h"

#include <string>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

#include <unistd.h>

using namespace tinyxml2;
using namespace std;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	std::string data_string(reinterpret_cast<const char*>(data), size);
	XMLDocument doc, doc_destination;
	XMLElement* element = doc.NewElement("First test data");

	element->SetName(data_string.c_str(), false);
	element->SetName(data_string.c_str(), true);
	
	element->SetText(data_string.c_str());

	element->SetAttribute("existing_atribute", "init data");
	element->SetAttribute("non_existing_atribute", data_string.c_str());

	element->SetAttribute("existing_atribute_other_type", 0xDEADBEEF);
	element->SetAttribute("existing_atribute_other_type", data_string.c_str());

	element->SetAttribute("non_existing_atribute", data_string.c_str());
	element->SetAttribute(data_string.c_str(), data_string.c_str());

	XMLPrinter printer;
    doc.Print( &printer );

	return 0;
}
