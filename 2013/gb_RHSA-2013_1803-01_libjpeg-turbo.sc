if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871098" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-12-17 11:54:50 +0530 (Tue, 17 Dec 2013)" );
	script_cve_id( "CVE-2013-6629", "CVE-2013-6630" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "RedHat Update for libjpeg-turbo RHSA-2013:1803-01" );
	script_tag( name: "affected", value: "libjpeg-turbo on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "The libjpeg-turbo package contains a library of functions for manipulating
JPEG images. It also contains simple client programs for accessing the
libjpeg functions.

An uninitialized memory read issue was found in the way libjpeg-turbo
decoded images with missing Start Of Scan (SOS) JPEG markers or Define
Huffman Table (DHT) JPEG markers. A remote attacker could create a
specially crafted JPEG image that, when decoded, could possibly lead to a
disclosure of potentially sensitive information. (CVE-2013-6629,
CVE-2013-6630)

All libjpeg-turbo users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2013:1803-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-December/msg00011.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libjpeg-turbo'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "libjpeg-turbo", rpm: "libjpeg-turbo~1.2.1~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libjpeg-turbo-debuginfo", rpm: "libjpeg-turbo-debuginfo~1.2.1~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libjpeg-turbo-devel", rpm: "libjpeg-turbo-devel~1.2.1~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
