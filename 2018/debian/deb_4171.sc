if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704171" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-8048" );
	script_name( "Debian Security Advisory DSA 4171-1 (ruby-loofah - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-13 00:00:00 +0200 (Fri, 13 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-22 09:15:00 +0000 (Fri, 22 Nov 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4171.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "ruby-loofah on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2.0.3-2+deb9u1.

We recommend that you upgrade your ruby-loofah packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/ruby-loofah" );
	script_tag( name: "summary", value: "The Shopify Application Security Team reported that ruby-loofah, a
general library for manipulating and transforming HTML/XML documents and
fragments, allows non-whitelisted attributes to be present in sanitized
output when input with specially-crafted HTML fragments. This might
allow to mount a code injection attack into a browser consuming
sanitized output." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-loofah", ver: "2.0.3-2+deb9u1", rls: "DEB9" ) )){
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

