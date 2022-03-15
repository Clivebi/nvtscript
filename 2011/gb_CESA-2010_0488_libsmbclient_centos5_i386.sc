if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2010-June/016734.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880642" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2010:0488" );
	script_cve_id( "CVE-2010-2063" );
	script_name( "CentOS Update for libsmbclient CESA-2010:0488 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsmbclient'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "libsmbclient on CentOS 5" );
	script_tag( name: "insight", value: "Samba is a suite of programs used by machines to share files, printers, and
  other information.

  An input sanitization flaw was found in the way Samba parsed client data. A
  malicious client could send a specially-crafted SMB packet to the Samba
  server, resulting in arbitrary code execution with the privileges of the
  Samba server (smbd). (CVE-2010-2063)

  Red Hat would like to thank the Samba team for responsibly reporting this
  issue. Upstream acknowledges Jun Mao as the original reporter.

  Users of Samba are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the smb service will be restarted automatically." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~3.0.33~3.29.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~3.0.33~3.29.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~3.0.33~3.29.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.0.33~3.29.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~3.0.33~3.29.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-swat", rpm: "samba-swat~3.0.33~3.29.el5_5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

