if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892703" );
	script_version( "2021-07-05T03:00:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-05 03:00:08 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-05 03:00:08 +0000 (Mon, 05 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for ieee-data (DLA-2703-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2703-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2703-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/908623" );
	script_xref( name: "URL", value: "https://bugs.debian.org/932711" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ieee-data'
  package(s) announced via the DLA-2703-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The ieee-data package, which provides the OUI and IAB listings of
identifiers assigned by IEEE Standards Association, ships a script
(update-ieee-data) which queries ieee.org to download the most recent
dataset and save it to /var/lib/ieee-data/.

This script broke for stretch at the end of 2018 when the URL changed." );
	script_tag( name: "affected", value: "'ieee-data' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
20160613.1+deb9u1.

We recommend that you upgrade your ieee-data packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ieee-data", ver: "20160613.1+deb9u1", rls: "DEB9" ) )){
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

