if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-March/msg00017.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870956" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-03-08 10:18:44 +0530 (Fri, 08 Mar 2013)" );
	script_cve_id( "CVE-2013-0809", "CVE-2013-1493" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "RHSA", value: "2013:0603-01" );
	script_name( "RedHat Update for java-1.7.0-openjdk RHSA-2013:0603-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "java-1.7.0-openjdk on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "These packages provide the OpenJDK 7 Java Runtime Environment and the
  OpenJDK 7 Software Development Kit.

  An integer overflow flaw was found in the way the 2D component handled
  certain sample model instances. A specially-crafted sample model instance
  could cause Java Virtual Machine memory corruption and, possibly, lead to
  arbitrary code execution with virtual machine privileges. (CVE-2013-0809)

  It was discovered that the 2D component did not properly reject certain
  malformed images. Specially-crafted raster parameters could cause Java
  Virtual Machine memory corruption and, possibly, lead to arbitrary code
  execution with virtual machine privileges. (CVE-2013-1493)

  This erratum also upgrades the OpenJDK package to IcedTea7 2.3.8. Refer to
  the NEWS file, linked to in the References, for further information.

  All users of java-1.7.0-openjdk are advised to upgrade to these updated
  packages, which resolve these issues. All running instances of OpenJDK Java
  must be restarted for the update to take effect." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.9~2.3.8.0.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-debuginfo", rpm: "java-1.7.0-openjdk-debuginfo~1.7.0.9~2.3.8.0.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.9~2.3.8.0.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.9~2.3.8.0.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.8.0.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.9~2.3.8.0.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

