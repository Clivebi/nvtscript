if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882896" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-05 14:03:32 +0530 (Tue, 05 Jun 2018)" );
	script_cve_id( "CVE-2018-1106" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for PackageKit CESA-2018:1224 centos7" );
	script_tag( name: "summary", value: "Check the version of PackageKit" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PackageKit is a D-Bus abstraction layer that allows the session user to
manage packages in a secure way using a cross-distribution,
cross-architecture API.

Security Fix(es):

  * PackageKit: authentication bypass allows to install signed packages
without administrator privileges (CVE-2018-1106)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Matthias Gerstner (SUSE) for reporting this
issue." );
	script_tag( name: "affected", value: "PackageKit on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:1224" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-May/022891.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "PackageKit", rpm: "PackageKit~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-command-not-found", rpm: "PackageKit-command-not-found~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-cron", rpm: "PackageKit-cron~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-glib", rpm: "PackageKit-glib~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-glib-devel", rpm: "PackageKit-glib-devel~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-gstreamer-plugin", rpm: "PackageKit-gstreamer-plugin~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-gtk3-module", rpm: "PackageKit-gtk3-module~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-yum", rpm: "PackageKit-yum~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "PackageKit-yum-plugin", rpm: "PackageKit-yum-plugin~1.1.5~2.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

