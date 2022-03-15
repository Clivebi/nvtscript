if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704906" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-21201", "CVE-2021-21202", "CVE-2021-21203", "CVE-2021-21204", "CVE-2021-21205", "CVE-2021-21207", "CVE-2021-21208", "CVE-2021-21209", "CVE-2021-21210", "CVE-2021-21211", "CVE-2021-21212", "CVE-2021-21213", "CVE-2021-21214", "CVE-2021-21215", "CVE-2021-21216", "CVE-2021-21217", "CVE-2021-21218", "CVE-2021-21219", "CVE-2021-21221", "CVE-2021-21222", "CVE-2021-21223", "CVE-2021-21224", "CVE-2021-21225", "CVE-2021-21226" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 15:14:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-30 03:00:33 +0000 (Fri, 30 Apr 2021)" );
	script_name( "Debian: Security Advisory for chromium (DSA-4906-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4906.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4906-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4906-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4906-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2021-21201
Gengming Liu and Jianyu Chen discovered a use-after-free issue.

CVE-2021-21202
David Erceg discovered a use-after-free issue in extensions.

CVE-2021-21203
asnine discovered a use-after-free issue in Blink/Webkit.

CVE-2021-21204
Tsai-Simek, Jeanette Ulloa, and Emily Voigtlander discovered a
use-after-free issue in Blink/Webkit.

CVE-2021-21205
Alison Huffman discovered a policy enforcement error.

CVE-2021-21207
koocola and Nan Wang discovered a use-after-free in the indexed database.

CVE-2021-21208
Ahmed Elsobky discovered a data validation error in the QR code scanner.

CVE-2021-21209
Tom Van Goethem discovered an implementation error in the Storage API.

CVE-2021-21210
@bananabr discovered an error in the networking implementation.

CVE-2021-21211
Akash Labade discovered an error in the navigation implementation.

CVE-2021-21212
Hugo Hue and Sze Yui Chau discovered an error in the network configuration
user interface.

CVE-2021-21213
raven discovered a use-after-free issue in the WebMIDI implementation.

CVE-2021-21214
A use-after-free issue was discovered in the networking implementation.

CVE-2021-21215
Abdulrahman Alqabandi discovered an error in the Autofill feature.

CVE-2021-21216
Abdulrahman Alqabandi discovered an error in the Autofill feature.

CVE-2021-21217
Zhou Aiting discovered use of uninitialized memory in the pdfium library.

CVE-2021-21218
Zhou Aiting discovered use of uninitialized memory in the pdfium library.

CVE-2021-21219
Zhou Aiting discovered use of uninitialized memory in the pdfium library.

CVE-2021-21221
Guang Gong discovered insufficient validation of untrusted input.

CVE-2021-21222
Guang Gong discovered a buffer overflow issue in the v8 javascript
library.

CVE-2021-21223
Guang Gong discovered an integer overflow issue.

CVE-2021-21224
Jose Martinez discovered a type error in the v8 javascript library.

CVE-2021-21225
Brendon Tiszka discovered an out-of-bounds memory access issue in the v8
javascript library.

CVE-2021-21226
Brendon Tiszka discovered a use-after-free issue in the networking
implementation." );
	script_tag( name: "affected", value: "'chromium' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 90.0.4430.85-1~deb10u1.

We recommend that you upgrade your chromium packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "90.0.4430.85-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-common", ver: "90.0.4430.85-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "90.0.4430.85-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "90.0.4430.85-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-sandbox", ver: "90.0.4430.85-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "90.0.4430.85-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}
exit( 0 );

