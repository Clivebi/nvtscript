if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704318" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-5934" );
	script_name( "Debian Security Advisory DSA 4318-1 (moin - security update)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-15 00:00:00 +0200 (Mon, 15 Oct 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-29 13:00:00 +0000 (Thu, 29 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4318.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "moin on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.9.9-1+deb9u1.

We recommend that you upgrade your moin packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/moin" );
	script_tag( name: "summary", value: "Nitin Venkatesh discovered a cross-site scripting vulnerability in moin,
a Python clone of WikiWiki. A remote attacker can conduct cross-site
scripting attacks via the GUI editor's link dialogue. This only affects
installations which have set up fckeditor (not enabled by default)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-moinmoin", ver: "1.9.9-1+deb9u1", rls: "DEB9" ) )){
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

