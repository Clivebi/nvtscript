if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891145" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-5595" );
	script_name( "Debian LTS: Security Advisory for zoneminder (DLA-1145-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-16 14:09:00 +0000 (Thu, 16 Feb 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/source-package/zoneminder" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "zoneminder on Debian Linux" );
	script_tag( name: "solution", value: "The application has been found to suffer from many other problems
such as SQL injection vulnerabilities, cross-site scripting issues,
cross-site request forgery, session fixation vulnerability. Due to the
amount of issues and to the relative invasiveness of the relevant patches,
those issues will not be fixed in Wheezy. We thus advise you to restrict
access to zoneminder to trusted users only. If you want to review the
list of ignored issues, you can check the referenced security tracker.

We recommend that you upgrade your zoneminder packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in zoneminder. This update
fixes only a serious file disclosure vulnerability (CVE-2017-5595)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "zoneminder", ver: "1.25.0-4+deb7u2", rls: "DEB7" ) )){
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

