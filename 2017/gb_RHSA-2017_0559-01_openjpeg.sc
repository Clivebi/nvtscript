if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871775" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2017-03-20 05:48:30 +0100 (Mon, 20 Mar 2017)" );
	script_cve_id( "CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9675", "CVE-2013-6045" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for openjpeg RHSA-2017:0559-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenJPEG is an open source library for reading and
writing image files in JPEG2000 format.

Security Fix(es):

  * Multiple integer overflow flaws, leading to heap-based buffer overflows,
were found in OpenJPEG. A specially crafted JPEG2000 image could cause an
application using OpenJPEG to crash or, potentially, execute arbitrary
code. (CVE-2016-5139, CVE-2016-5158, CVE-2016-5159, CVE-2016-7163)

  * A vulnerability was found in the patch for CVE-2013-6045 for OpenJPEG. A
specially crafted JPEG2000 image, when read by an application using
OpenJPEG, could cause heap-based buffer overflows leading to a crash or,
potentially, arbitrary code execution. (CVE-2016-9675)

The CVE-2016-9675 issue was discovered by Doran Moppert (Red Hat Product
Security)." );
	script_tag( name: "affected", value: "openjpeg on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:0559-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-March/msg00040.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "openjpeg-debuginfo", rpm: "openjpeg-debuginfo~1.3~16.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openjpeg-libs", rpm: "openjpeg-libs~1.3~16.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

