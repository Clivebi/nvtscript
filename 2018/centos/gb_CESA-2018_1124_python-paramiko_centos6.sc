if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882872" );
	script_version( "2021-05-21T08:11:46+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:11:46 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-03 05:30:09 +0200 (Thu, 03 May 2018)" );
	script_cve_id( "CVE-2018-7750" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:31:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for python-paramiko CESA-2018:1124 centos6" );
	script_tag( name: "summary", value: "Check the version of python-paramiko" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The python-paramiko package provides a Python
  module that implements the SSH2 protocol for encrypted and authenticated
  connections to remote machines. Unlike SSL, the SSH2 protocol does not require
  hierarchical certificates signed by a powerful central authority. The protocol
  also includes the ability to open arbitrary channels to remote services across
  an encrypted tunnel.

Security Fix(es):

  * python-paramiko: Authentication bypass in transport.py (CVE-2018-7750)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section." );
	script_tag( name: "affected", value: "python-paramiko on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:1124" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-May/022821.html" );
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
	if(( res = isrpmvuln( pkg: "python-paramiko", rpm: "python-paramiko~1.7.5~4.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

