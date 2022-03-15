if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892755" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2021-38173" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-17 17:16:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-09-06 01:00:07 +0000 (Mon, 06 Sep 2021)" );
	script_name( "Debian LTS: Security Advisory for btrbk (DLA-2755-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/09/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2755-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2755-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'btrbk'
  package(s) announced via the DLA-2755-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in btrbk, a backup tool for btrfs subvolumes.
Due to mishandling of remote hosts filtering SSH commands using
ssh_filter_btrbk.sh in authorized_keys an arbitrary code execution would
have been allowed." );
	script_tag( name: "affected", value: "'btrbk' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.24.0-1+deb9u1.

We recommend that you upgrade your btrbk packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "btrbk", ver: "0.24.0-1+deb9u1", rls: "DEB9" ) )){
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

