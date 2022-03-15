if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871107" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-12-23 12:39:35 +0530 (Mon, 23 Dec 2013)" );
	script_cve_id( "CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "RedHat Update for openjpeg RHSA-2013:1850-01" );
	script_tag( name: "affected", value: "openjpeg on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "OpenJPEG is an open source library for reading and writing image files in
JPEG 2000 format.

Multiple heap-based buffer overflow flaws were found in OpenJPEG.
An attacker could create a specially crafted OpenJPEG image that, when
opened, could cause an application using openjpeg to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2013-6045, CVE-2013-6054)

Multiple denial of service flaws were found in OpenJPEG. An attacker could
create a specially crafted OpenJPEG image that, when opened, could cause an
application using openjpeg to crash (CVE-2013-1447, CVE-2013-6052)

Red Hat would like to thank Raphael Geissert for reporting these issues.

Users of OpenJPEG are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications using OpenJPEG must be restarted for the update to take
effect." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2013:1850-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-December/msg00032.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg'
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
	if(( res = isrpmvuln( pkg: "openjpeg-debuginfo", rpm: "openjpeg-debuginfo~1.3~10.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openjpeg-libs", rpm: "openjpeg-libs~1.3~10.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

