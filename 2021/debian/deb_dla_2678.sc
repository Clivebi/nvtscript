if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892678" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-26247" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 21:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-07 03:00:16 +0000 (Mon, 07 Jun 2021)" );
	script_name( "Debian LTS: Security Advisory for ruby-nokogiri (DLA-2678-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/06/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2678-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2678-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/978967" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-nokogiri'
  package(s) announced via the DLA-2678-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An XXE vulnerability was found in Nokogiri, a Rubygem providing HTML, XML, SAX,
and Reader parsers with XPath and CSS selector support.

XML Schemas parsed by Nokogiri::XML::Schema were trusted by default, allowing
external resources to be accessed over the network, potentially enabling XXE or
SSRF attacks. The new default behavior is to treat all input as untrusted.
The upstream advisory provides further information how to mitigate the problem
or restore the old behavior again." );
	script_tag( name: "affected", value: "'ruby-nokogiri' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.6.8.1-1+deb9u1.

We recommend that you upgrade your ruby-nokogiri packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-nokogiri", ver: "1.6.8.1-1+deb9u1", rls: "DEB9" ) )){
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

