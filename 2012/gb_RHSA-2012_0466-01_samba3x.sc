if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-April/msg00003.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870584" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-11 10:59:47 +0530 (Wed, 11 Apr 2012)" );
	script_cve_id( "CVE-2012-1182" );
	script_xref( name: "RHSA", value: "2012:0466-01" );
	script_name( "RedHat Update for samba3x RHSA-2012:0466-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba3x'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "samba3x on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Samba is an open-source implementation of the Server Message Block (SMB) or
  Common Internet File System (CIFS) protocol, which allows PC-compatible
  machines to share files, printers, and other information.

  A flaw in the Samba suite's Perl-based DCE/RPC IDL (PIDL) compiler, used
  to generate code to handle RPC calls, resulted in multiple buffer overflows
  in Samba. A remote, unauthenticated attacker could send a specially-crafted
  RPC request that would cause the Samba daemon (smbd) to crash or, possibly,
  execute arbitrary code with the privileges of the root user.
  (CVE-2012-1182)

  Users of Samba are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the smb service will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "samba3x", rpm: "samba3x~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-client", rpm: "samba3x-client~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-common", rpm: "samba3x-common~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-debuginfo", rpm: "samba3x-debuginfo~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-doc", rpm: "samba3x-doc~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-domainjoin-gui", rpm: "samba3x-domainjoin-gui~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-swat", rpm: "samba3x-swat~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-winbind", rpm: "samba3x-winbind~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-winbind-devel", rpm: "samba3x-winbind-devel~3.5.10~0.108.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

