function loginRedirect(req, res) {
  return res.redirect(req.query.next);
}
