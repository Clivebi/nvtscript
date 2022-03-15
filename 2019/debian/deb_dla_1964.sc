if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891964" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-14287" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-10-18 02:00:06 +0000 (Fri, 18 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for sudo (DLA-1964-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1964-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942322" );
	script_xref( name: "URL", value: "https://www.sudo.ws/alerts/minus_1_uid.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the DLA-1964-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In sudo, a program that provides limited super user privileges to
specific users, an attacker with access to a Runas ALL sudoer account
can bypass certain policy blacklists and session PAM modules, and can
cause incorrect logging, by invoking sudo with a crafted user ID. For
example, this allows bypass of (ALL,!root) configuration for a
'sudo -u#-1' command.

See the referenced vendor advisory for further information." );
	script_tag( name: "affected", value: "'sudo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.8.10p3-1+deb8u6.

We recommend that you upgrade your sudo packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sudo", ver: "1.8.10p3-1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.8.10p3-1+deb8u6", rls: "DEB8" ) )){
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

