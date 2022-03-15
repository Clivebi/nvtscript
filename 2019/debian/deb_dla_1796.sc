if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891796" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-20 13:29:00 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-21 02:00:23 +0000 (Tue, 21 May 2019)" );
	script_name( "Debian LTS: Security Advisory for jruby (DLA-1796-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1796-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/895778" );
	script_xref( name: "URL", value: "https://bugs.debian.org/925987" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jruby'
  package(s) announced via the DLA-1796-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in jruby, Java
implementation of the Ruby programming language.

CVE-2018-1000074

Deserialization of Untrusted Data vulnerability in owner command
that can result in code execution. This attack appear to be
exploitable via victim must run the `gem owner` command on a gem
with a specially crafted YAML file

CVE-2018-1000075

an infinite loop caused by negative size vulnerability in ruby gem
package tar header that can result in a negative size could cause an
infinite loop

CVE-2018-1000076

Improper Verification of Cryptographic Signature vulnerability in
package.rb that can result in a mis-signed gem could be installed,
as the tarball would contain multiple gem signatures.

CVE-2018-1000077

Improper Input Validation vulnerability in ruby gems specification
homepage attribute that can result in a malicious gem could set an
invalid homepage URL

CVE-2018-1000078

Cross Site Scripting (XSS) vulnerability in gem server display of
homepage attribute that can result in XSS. This attack appear to be
exploitable via the victim must browse to a malicious gem on a
vulnerable gem server

CVE-2019-8321

Gem::UserInteraction#verbose calls say without escaping, escape
sequence injection is possible

CVE-2019-8322

The gem owner command outputs the contents of the API response
directly to stdout. Therefore, if the response is crafted, escape
sequence injection may occur

CVE-2019-8323

Gem::GemcutterUtilities#with_response may output the API response to
stdout as it is. Therefore, if the API side modifies the response,
escape sequence injection may occur.

CVE-2019-8324

A crafted gem with a multi-line name is not handled correctly.
Therefore, an attacker could inject arbitrary code to the stub line
of gemspec

CVE-2019-8325

Gem::CommandManager#run calls alert_error without escaping, escape
sequence injection is possible. (There are many ways to cause an
error.)" );
	script_tag( name: "affected", value: "'jruby' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.5.6-9+deb8u1.

We recommend that you upgrade your jruby packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "jruby", ver: "1.5.6-9+deb8u1", rls: "DEB8" ) )){
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

