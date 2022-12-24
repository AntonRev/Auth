totp_sync_template = '''
<!DOCTYPE html>
<html>

<body>
	<canvas id="qr"></canvas>

	<script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
	<script>
		(function () {
    var qr = new QRious({
      element: document.getElementById('qr'),
      value: '%s'
    });
  })();
	</script>
	<p>Просканируйте QR-код с помощью TOTP-приложения и введите код</p>
	<form enctype='application/json' method="post" action="/sync">
		<input required name="code">
		<button type="submit">Синхронизация</button>
	</form>
</body>

</html>
'''

totp_check_template = '''
<!DOCTYPE html>
<html>

<body>
	<form enctype='application/json' method="post" action="/check/%s">
		<input required name="code">
		<button type="submit">Проверка</button>
	</form>
</body>

</html>
'''
