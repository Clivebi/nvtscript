if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871310" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-01-29 05:14:09 +0100 (Thu, 29 Jan 2015)" );
	script_cve_id( "CVE-2014-9130" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "RedHat Update for libyaml RHSA-2015:0100-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libyaml'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "YAML is a data serialization format designed for human readability and
interaction with scripting languages. LibYAML is a YAML parser and emitter
written in C.

An assertion failure was found in the way the libyaml library parsed
wrapped strings. An attacker able to load specially crafted YAML input into
an application using libyaml could cause the application to crash.
(CVE-2014-9130)

All libyaml users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. All running applications
linked against the libyaml library must be restarted for this update to
take effect." );
	script_tag( name: "affected", value: "libyaml on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:0100-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-January/msg00039.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6)" );
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
	if(( res = isrpmvuln( pkg: "libyaml", rpm: "libyaml~0.1.4~11.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libyaml-debuginfo", rpm: "libyaml-debuginfo~0.1.4~11.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "libyaml", rpm: "libyaml~0.1.3~4.el6_6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libyaml-debuginfo", rpm: "libyaml-debuginfo~0.1.3~4.el6_6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

