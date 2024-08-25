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
#include <list>

#include <unistd.h>

using namespace tinyxml2;
using namespace std;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	std::string data_string(reinterpret_cast<const char*>(data), size);
	
	XMLDocument doc1(true, PRESERVE_WHITESPACE);
	XMLDocument doc2(true, COLLAPSE_WHITESPACE);
	XMLDocument doc3(true, PEDANTIC_WHITESPACE);
	XMLDocument doc4(false, PRESERVE_WHITESPACE);
	XMLDocument doc5(false, COLLAPSE_WHITESPACE);
	XMLDocument doc6(false, PEDANTIC_WHITESPACE);

	XMLDocument doc_destination1(true, PRESERVE_WHITESPACE);
	XMLDocument doc_destination2(true, COLLAPSE_WHITESPACE);
	XMLDocument doc_destination3(true, PEDANTIC_WHITESPACE);
	XMLDocument doc_destination4(false, PRESERVE_WHITESPACE);
	XMLDocument doc_destination5(false, COLLAPSE_WHITESPACE);
	XMLDocument doc_destination6(false, PEDANTIC_WHITESPACE);

	list<XMLDocument*> docs = {
		&doc1,
		&doc2,
		&doc3,
		&doc4,
		&doc5,
		&doc6
	};
	list<XMLDocument*> doc_destinations = {
		&doc_destination1,
		&doc_destination2,
		&doc_destination3,
		&doc_destination4,
		&doc_destination5,
		&doc_destination6
	};

	XMLPrinter printer;

	for(XMLDocument* doc : docs) {
		doc->Parse(data_string.c_str());
		for(XMLDocument* doc_destination : doc_destinations) {
			doc->DeepCopy(doc_destination);
			doc_destination->Print( &printer );
		}
	}

	return 0;
}
