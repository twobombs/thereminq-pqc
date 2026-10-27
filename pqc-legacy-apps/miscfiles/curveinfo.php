<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Curve Information</title>
</head>
<body>
    <h1>Your SSL Curve Information</h1>

    <?php
        $ssl_curve = $_SERVER['SSL_CURVE'];

        if ($ssl_curve === '0x6399') {
            echo "<p class='secure'>You are using X25519Kyber768Draft00 which is post-quantum secure.</p>";
        } elsif ($ssl_curve === '0x4588') {
            echo "<p class='secure'>You are using X25519MLKEM768, which is post-quantum secure.</p>";
        } else {
            echo "<p class='not-secure'>You are using SSL Curve: {$ssl_curve} which is not post-quantum secure.</p>";
        }
    ?>

</body>
</html>
