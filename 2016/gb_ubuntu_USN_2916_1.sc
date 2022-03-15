if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842672" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-03 06:27:02 +0100 (Thu, 03 Mar 2016)" );
	script_cve_id( "CVE-2013-7422", "CVE-2014-4330", "CVE-2016-2381" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for perl USN-2916-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Perl incorrectly
  handled certain regular expressions with an invalid backreference.
  An attacker could use this issue to cause Perl to crash, resulting
  in a denial of service, or possibly execute arbitrary code. (CVE-2013-7422)

  Markus Vervier discovered that Perl incorrectly handled nesting in the
  Data::Dumper module. An attacker could use this issue to cause Perl to
  consume memory and crash, resulting in a denial of service. (CVE-2014-4330)

  Stephane Chazelas discovered that Perl incorrectly handled duplicate
  environment variables. An attacker could possibly use this issue to bypass
  the taint protection mechanism. (CVE-2016-2381)" );
	script_tag( name: "affected", value: "perl on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2916-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2916-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.18.2-2ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.14.2-6ubuntu2.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "perl", ver: "5.20.2-6ubuntu0.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

