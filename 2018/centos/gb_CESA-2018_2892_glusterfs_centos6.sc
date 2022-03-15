if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882960" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-10-10 06:50:45 +0200 (Wed, 10 Oct 2018)" );
	script_cve_id( "CVE-2018-10911" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for glusterfs CESA-2018:2892 centos6" );
	script_tag( name: "summary", value: "Check the version of glusterfs" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "GlusterFS is a key building block of Red Hat
  Gluster Storage. It is based on a stackable user-space design and can deliver
  exceptional performance for diverse workloads. GlusterFS aggregates various
  storage servers over network interconnections into one large, parallel network
  file system.

The glusterfs packages have been upgraded to upstream version 3.12.2, which
provides a number of bug fixes over the previous version. (BZ#1594203)

Security Fix(es):

  * glusterfs: Improper deserialization in dict.c:dict_unserialize() can
allow attackers to read arbitrary memory (CVE-2018-10911)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Michael Hanselmann (hansmi.ch) for reporting
this issue." );
	script_tag( name: "affected", value: "glusterfs on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:2892" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-October/023058.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "glusterfs", rpm: "glusterfs~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-api", rpm: "glusterfs-api~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-api-devel", rpm: "glusterfs-api-devel~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-cli", rpm: "glusterfs-cli~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-client-xlators", rpm: "glusterfs-client-xlators~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-devel", rpm: "glusterfs-devel~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-fuse", rpm: "glusterfs-fuse~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-libs", rpm: "glusterfs-libs~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glusterfs-rdma", rpm: "glusterfs-rdma~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python2-gluster", rpm: "python2-gluster~3.12.2~18.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

