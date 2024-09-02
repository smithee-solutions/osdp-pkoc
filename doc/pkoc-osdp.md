### Set-Up ###

- create pkoc-settings.json in /opt/osdp/etc.  To set the smartcard reader,
use "reader":"1". To debug, use verbosity:9.
- create /opt/osdp/log

```
// program pkoc-init-od
// program pkoc mfgrep action routine
// program pkoc-reader


the scenario is this:

acu sends next-transaction
pd initiates card read
pd sends card present
acu send auth request
pd interacts with card to fulfill auth request
pd sends auth response
acu validates auth response
acu declares card read.
```



\newpage {}

```
   Copyright [2024] Smithee Solutions LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

