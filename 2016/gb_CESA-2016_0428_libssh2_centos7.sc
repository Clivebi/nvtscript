if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882419" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-11 06:01:56 +0100 (Fri, 11 Mar 2016)" );
	script_cve_id( "CVE-2016-0787" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libssh2 CESA-2016:0428 centos7" );
	script_tag( name: "summary", value: "Check the version of libssh2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libssh2 packages provide a library
that implements the SSHv2 protocol.

A type confusion issue was found in the way libssh2 generated ephemeral
secrets for the diffie-hellman-group1 and diffie-hellman-group14 key
exchange methods. This would cause an SSHv2 Diffie-Hellman handshake to use
significantly less secure random parameters. (CVE-2016-0787)

Red Hat would like to thank Aris Adamantiadis for reporting this issue.

All libssh2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing these
updated packages, all running applications using libssh2 must be restarted
for this update to take effect." );
	script_tag( name: "affected", value: "libssh2 on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0428" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-March/021727.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "libssh2", rpm: "libssh2~1.4.3~10.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libssh2-devel", rpm: "libssh2-devel~1.4.3~10.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libssh2-docs", rpm: "libssh2-docs~1.4.3~10.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

