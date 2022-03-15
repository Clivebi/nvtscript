if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844738" );
	script_version( "2020-12-08T04:03:06+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-08 04:03:06 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-01 04:00:53 +0000 (Tue, 01 Dec 2020)" );
	script_name( "Ubuntu: Security Advisory for mysql-8.0 (USN-4651-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU20\\.04 LTS" );
	script_xref( name: "USN", value: "4651-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005784.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-4651-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Tom Reynolds discovered that due to a packaging error, the MySQL X Plugin
was listening to all network interfaces by default, contrary to
expectations.

This update changes the default MySQL configuration to bind the MySQL X
Plugin to localhost only. This change may impact environments where the
MySQL X Plugin needs to be accessible from the network. The
mysqlx-bind-address setting in the /etc/mysql/mysql.conf.d/mysqld.cnf file
can be modified to allow network access." );
	script_tag( name: "affected", value: "'mysql-8.0' package(s) on Ubuntu 20.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "mysql-server-8.0", ver: "8.0.22-0ubuntu0.20.04.3", rls: "UBUNTU20.04 LTS" ) )){
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
}
exit( 0 );

