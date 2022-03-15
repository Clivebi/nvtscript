if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871318" );
	script_version( "$Revision: 12380 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:03:48 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-02-25 05:42:23 +0100 (Wed, 25 Feb 2015)" );
	script_cve_id( "CVE-2015-0240" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for samba3x RHSA-2015:0249-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba3x'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Samba is an open-source implementation of the Server Message Block (SMB) or
Common Internet File System (CIFS) protocol, which allows PC-compatible
machines to share files, printers, and other information.

An uninitialized pointer use flaw was found in the Samba daemon (smbd).
A malicious Samba client could send specially crafted netlogon packets
that, when processed by smbd, could potentially lead to arbitrary code
execution with the privileges of the user running smbd (by default, the
root user). (CVE-2015-0240)

For additional information about this flaw, see the referenced Knowledgebase article.

Red Hat would like to thank the Samba project for reporting this issue.
Upstream acknowledges Richard van Eeden of Microsoft Vulnerability Research
as the original reporter of this issue.

All Samba users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, the smb service will be restarted automatically." );
	script_tag( name: "affected", value: "samba3x on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:0249-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-February/msg00029.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_xref( name: "URL", value: "https://access.redhat.com/articles/1346913" );
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
	if(( res = isrpmvuln( pkg: "samba3x", rpm: "samba3x~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-client", rpm: "samba3x-client~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-common", rpm: "samba3x-common~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-debuginfo", rpm: "samba3x-debuginfo~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-doc", rpm: "samba3x-doc~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-domainjoin-gui", rpm: "samba3x-domainjoin-gui~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-swat", rpm: "samba3x-swat~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-winbind", rpm: "samba3x-winbind~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-winbind-devel", rpm: "samba3x-winbind-devel~3.6.23~9.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

