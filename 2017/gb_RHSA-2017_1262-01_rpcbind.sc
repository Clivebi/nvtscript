if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871816" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-22 06:52:06 +0200 (Mon, 22 May 2017)" );
	script_cve_id( "CVE-2017-8779" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for rpcbind RHSA-2017:1262-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpcbind'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The rpcbind utility is a server that
converts Remote Procedure Call (RPC) program numbers into universal addresses.
It must be running on the host to be able to make RPC calls on a server on that
machine.

Security Fix(es):

  * It was found that due to the way rpcbind uses libtirpc (libntirpc), a
memory leak can occur when parsing specially crafted XDR messages. An
attacker sending thousands of messages to rpcbind could cause its memory
usage to grow without bound, eventually causing it to be terminated by the
OOM killer. (CVE-2017-8779)" );
	script_tag( name: "affected", value: "rpcbind on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:1262-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-May/msg00028.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "rpcbind", rpm: "rpcbind~0.2.0~38.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rpcbind-debuginfo", rpm: "rpcbind-debuginfo~0.2.0~38.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

