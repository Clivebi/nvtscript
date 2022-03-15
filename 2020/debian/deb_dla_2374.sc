if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892374" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-17489" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 14:46:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-09-16 03:00:10 +0000 (Wed, 16 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for gnome-shell (DLA-2374-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2374-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/968311" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-shell'
  package(s) announced via the DLA-2374-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an issue around revealing passwords
in the 'gnome-shell' component of the GNOME desktop.

In certain configurations, when logging out of an account the
password box from the login dialog could reappear with the password
visible in cleartext." );
	script_tag( name: "affected", value: "'gnome-shell' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
3.22.3-3+deb9u1.

We recommend that you upgrade your gnome-shell packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gnome-shell", ver: "3.22.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnome-shell-common", ver: "3.22.3-3+deb9u1", rls: "DEB9" ) )){
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

