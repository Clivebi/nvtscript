if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871482" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-20 06:19:58 +0100 (Fri, 20 Nov 2015)" );
	script_cve_id( "CVE-2014-8119" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for netcf RHSA-2015:2248-03" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netcf'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The netcf packages contain a library for
modifying the network configuration of a system. Network configuration is expressed
in a platform-independent XML format, which netcf translates into changes to the
system's 'native' network configuration files.

A denial of service flaw was found in netcf. A specially crafted interface
name could cause an application using netcf (such as the libvirt daemon) to
crash. (CVE-2014-8119)

This issue was discovered by Hao Liu of Red Hat.

The netcf packages have been upgraded to upstream version 0.2.8, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#1206680)

Users of netcf are advised to upgrade to these updated packages, which fix
these bugs and add these enhancements." );
	script_tag( name: "affected", value: "netcf on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:2248-03" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-November/msg00036.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "netcf-debuginfo", rpm: "netcf-debuginfo~0.2.8~1.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "netcf-libs", rpm: "netcf-libs~0.2.8~1.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

