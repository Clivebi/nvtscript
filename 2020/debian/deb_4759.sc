if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704759" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-24654" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-11 11:15:00 +0000 (Mon, 11 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-09-05 03:00:04 +0000 (Sat, 05 Sep 2020)" );
	script_name( "Debian: Security Advisory for ark (DSA-4759-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4759.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4759-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ark'
  package(s) announced via the DSA-4759-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Fabian Vogt reported that the Ark archive manager did not sanitise
extraction paths, which could result in maliciously crafted archives
with symlinks writing outside the extraction directory." );
	script_tag( name: "affected", value: "'ark' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 4:18.08.3-1+deb10u2.

We recommend that you upgrade your ark packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ark", ver: "4:18.08.3-1+deb10u2", rls: "DEB10" ) )){
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
