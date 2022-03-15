if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841753" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-17 13:43:12 +0530 (Mon, 17 Mar 2014)" );
	script_cve_id( "CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for cups USN-2144-1" );
	script_tag( name: "affected", value: "cups on Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Florian Weimer discovered that the pdftoopvp filter bundled
in the CUPS package incorrectly handled memory. An attacker could possibly use
this issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6474, CVE-2013-6475)

Florian Weimer discovered that the pdftoopvp filter bundled in the CUPS
package did not restrict driver directories. An attacker could possibly use
this issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6476)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2144-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2144-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "cups", ver: "1.4.3-1ubuntu1.10", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

