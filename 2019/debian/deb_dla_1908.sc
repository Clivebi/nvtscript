if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891908" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-09-03 02:00:17 +0000 (Tue, 03 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for pump (DLA-1908-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1908-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/933674" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pump'
  package(s) announced via the DLA-1908-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an arbitrary code execution
vulnerability in the pump BOOTP and DHCP client.

When copying the body of the server response, the ethernet packet
length could be forged leading to being able to overwrite up to
'ETH_FRAME_LEN - sizeof(*ipHdr) - sizeof(*udpHdr) - sizeof(*bresp)'
bytes of stack memory.

Thanks to <ltspro2@secmail.pro> for the report and patch." );
	script_tag( name: "affected", value: "'pump' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in pump version
0.8.24-7+deb8u1.

We recommend that you upgrade your pump packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pump", ver: "0.8.24-7+deb8u1", rls: "DEB8" ) )){
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

