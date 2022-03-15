if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892053" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-18179" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-23 15:15:00 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-01-02 03:00:07 +0000 (Thu, 02 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for otrs2 (DLA-2053-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2053-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/945251" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'otrs2'
  package(s) announced via the DLA-2053-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An attacker who is logged into OTRS as an agent is able to list
tickets assigned to other agents, which are in the queue where
attacker doesn't have permissions." );
	script_tag( name: "affected", value: "'otrs2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.3.18-1+deb8u12.

We recommend that you upgrade your otrs2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "otrs", ver: "3.3.18-1+deb8u12", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "otrs2", ver: "3.3.18-1+deb8u12", rls: "DEB8" ) )){
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

