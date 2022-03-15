if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892639" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-12460" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-31 04:15:00 +0000 (Mon, 31 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-26 03:00:13 +0000 (Mon, 26 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for opendmarc (DLA-2639-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2639-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2639-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/966464" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opendmarc'
  package(s) announced via the DLA-2639-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that OpenDMARC, a milter implementation of DMARC,
has improper null termination in the function opendmarc_xml_parse that
can result in a one-byte heap overflow in opendmarc_xml when parsing a
specially crafted DMARC aggregate report. This can cause remote memory
corruption when a '\\0' byte overwrites the heap metadata of the next
chunk and its PREV_INUSE flag." );
	script_tag( name: "affected", value: "'opendmarc' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.3.2-2+deb9u3.

We recommend that you upgrade your opendmarc packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopendmarc-dev", ver: "1.3.2-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopendmarc2", ver: "1.3.2-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "opendmarc", ver: "1.3.2-2+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rddmarc", ver: "1.3.2-2+deb9u3", rls: "DEB9" ) )){
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

